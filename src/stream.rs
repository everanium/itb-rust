//! Incremental stream sessions over an open [`Pipeline`].
//!
//! A session is a dumb byte pump: [`EncryptStream`] takes plaintext
//! in through `write` (or `io::Write`) and yields wire through `read`
//! / `drain_all` (or `io::Read` after `end`); [`DecryptStream`] is
//! the mirror (wire in, plaintext out). All chunking, MAC, envelope,
//! and wire-format decisions stay inside libitb3. Dropping a session
//! cancels it and frees the Go-side state; the borrow on the parent
//! [`Pipeline`] keeps a session from outliving it.

use std::ffi::c_int;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use crate::error::{ItbResult, check};
use crate::ffi;
use crate::pipeline::Pipeline;

/// Feed / drain slice size used by the pump loops.
const PUMP_BUF: usize = 1 << 20;

struct Session<'a> {
    handle: usize,
    ended: bool,
    _pipe: PhantomData<&'a Pipeline>,
}

impl Session<'_> {
    fn write(&mut self, src: &[u8]) -> ItbResult<()> {
        let s = ffi::syms()?;
        // SAFETY: src is live for the call; the handle came from a
        // Begin on the borrowed Pipeline.
        check(unsafe { (s.ITB_Triple_StreamWrite)(self.handle, src.as_ptr().cast(), src.len()) })
    }

    fn end(&mut self) -> ItbResult<()> {
        let s = ffi::syms()?;
        // SAFETY: handle-only call, idempotent on the Go side.
        check(unsafe { (s.ITB_Triple_StreamEnd)(self.handle) })?;
        self.ended = true;
        Ok(())
    }

    fn read(&mut self, dst: &mut [u8]) -> ItbResult<(usize, bool)> {
        let s = ffi::syms()?;
        let mut n = 0usize;
        let mut fin: c_int = 0;
        // SAFETY: dst is writable for dst.len() bytes; n / fin are
        // valid out-params.
        check(unsafe {
            (s.ITB_Triple_StreamRead)(
                self.handle,
                dst.as_mut_ptr().cast(),
                dst.len(),
                &mut n,
                &mut fin,
            )
        })?;
        Ok((n, fin != 0))
    }

    fn drain_all(&mut self, dst: &mut Vec<u8>) -> ItbResult<()> {
        if !self.ended {
            self.end()?;
        }
        let mut buf = vec![0u8; PUMP_BUF];
        loop {
            let (n, fin) = self.read(&mut buf)?;
            dst.extend_from_slice(&buf[..n]);
            if fin {
                return Ok(());
            }
        }
    }

    fn pump<R: Read, W: Write>(&mut self, mut src: R, mut dst: W) -> ItbResult<()> {
        let mut inbuf = vec![0u8; PUMP_BUF];
        let mut outbuf = vec![0u8; PUMP_BUF];
        loop {
            let n = src.read(&mut inbuf)?;
            if n == 0 {
                break;
            }
            self.write(&inbuf[..n])?;
            // Drain whatever the chain has produced so far; a read
            // before end() never blocks.
            loop {
                let (m, _) = self.read(&mut outbuf)?;
                if m == 0 {
                    break;
                }
                dst.write_all(&outbuf[..m])?;
            }
        }
        self.end()?;
        loop {
            let (m, fin) = self.read(&mut outbuf)?;
            if m > 0 {
                dst.write_all(&outbuf[..m])?;
            }
            if fin {
                break;
            }
        }
        dst.flush()?;
        Ok(())
    }

    /// `io::Read` bridge over the session's output side. Valid after
    /// `end()` — a pre-end empty spool cannot be distinguished from
    /// EOF, so it is reported as an error rather than a false EOF.
    fn read_io(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let (n, fin) = self.read(buf).map_err(io::Error::from)?;
            if n > 0 {
                return Ok(n);
            }
            if fin {
                return Ok(0);
            }
            if !self.ended {
                return Err(io::Error::other(
                    "itb: io::Read on a stream session requires end() first",
                ));
            }
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        if let Ok(s) = ffi::syms() {
            // SAFETY: StreamFree cancels and releases the session from
            // any state. The status is deliberately ignored on the
            // drop path.
            let _ = unsafe { (s.ITB_Triple_StreamFree)(self.handle) };
        }
        self.handle = 0;
    }
}

fn begin<'a>(pipe: &'a Pipeline, encrypt: bool) -> ItbResult<Session<'a>> {
    let s = ffi::syms()?;
    let f = if encrypt {
        s.ITB_Triple_EncryptStreamBegin
    } else {
        s.ITB_Triple_DecryptStreamBegin
    };
    let mut handle = 0usize;
    // SAFETY: handle is a valid out-param; the Pipeline handle is live
    // for the duration of the call (and the returned session borrows
    // the Pipeline so it cannot outlive it).
    check(unsafe { f(pipe.raw_handle(), &mut handle) })?;
    Ok(Session {
        handle,
        ended: false,
        _pipe: PhantomData,
    })
}

macro_rules! stream_type {
    ($(#[$doc:meta])* $name:ident, $encrypt:literal) => {
        $(#[$doc])*
        pub struct $name<'a> {
            sess: Session<'a>,
        }

        impl<'a> $name<'a> {
            pub(crate) fn begin(pipe: &'a Pipeline) -> ItbResult<Self> {
                Ok(Self { sess: begin(pipe, $encrypt)? })
            }

            /// Feeds `src` into the session. Blocks until the cipher
            /// chain accepts the bytes; errors are sticky.
            pub fn write(&mut self, src: &[u8]) -> ItbResult<()> {
                self.sess.write(src)
            }

            /// Signals end-of-input. Idempotent; `write` after `end`
            /// fails with `BadInput`.
            pub fn end(&mut self) -> ItbResult<()> {
                self.sess.end()
            }

            /// Drains up to `dst.len()` produced bytes; returns
            /// `(bytes_read, finished)`. Partial drains are normal.
            /// After `end`, an empty-spool read blocks until the
            /// terminal bytes arrive or the session errors.
            pub fn read(&mut self, dst: &mut [u8]) -> ItbResult<(usize, bool)> {
                self.sess.read(dst)
            }

            /// Calls `end` (if not yet called) and appends every
            /// remaining output byte to `dst`.
            pub fn drain_all(&mut self, dst: &mut Vec<u8>) -> ItbResult<()> {
                self.sess.drain_all(dst)
            }

            pub(crate) fn pump<R: Read, W: Write>(&mut self, src: R, dst: W) -> ItbResult<()> {
                self.sess.pump(src, dst)
            }
        }

        /// Input side of the session (plaintext for encrypt, wire for
        /// decrypt). Flush is a no-op — chunk boundaries are libitb3's
        /// decision.
        impl Write for $name<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.sess.write(buf)?;
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        /// Output side of the session. Valid after `end()`; returns
        /// `Ok(0)` once the session output is fully drained.
        impl Read for $name<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.sess.read_io(buf)
            }
        }
    };
}

stream_type!(
    /// Incremental encrypt session: plaintext in, wire out.
    EncryptStream,
    true
);
stream_type!(
    /// Incremental decrypt session: wire in, plaintext out.
    DecryptStream,
    false
);
