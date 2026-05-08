//! File-like streaming wrappers over the one-shot ITB encrypt /
//! decrypt API.
//!
//! ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
//! container size limit). Streaming larger payloads simply means
//! slicing the input into chunks at the binding layer, encrypting
//! each chunk through the regular FFI path, and concatenating the
//! results. The reverse operation walks a concatenated chunk stream
//! by reading the chunk header, calling [`crate::parse_chunk_len`] to
//! learn the chunk's body length, reading that many bytes, and
//! decrypting the single chunk.
//!
//! Both struct-based wrappers ([`StreamEncryptor`], [`StreamDecryptor`]
//! and their Triple counterparts) and free-function convenience
//! wrappers ([`encrypt_stream`], [`decrypt_stream`], plus Triple
//! variants) are provided. Memory peak is bounded by `chunk_size`
//! (default 16 MB), regardless of the total payload length.
//!
//! The Triple-Ouroboros (7-seed) variants share the same I/O contract
//! and only differ in the seed list passed to the constructor.
//!
//! # Warning
//!
//! Do not call [`crate::set_nonce_bits`] between writes on the same
//! stream. The chunks are encrypted under the active nonce-size at
//! the moment each chunk is flushed; switching nonce-bits mid-stream
//! produces a chunk header layout the paired decryptor (which
//! snapshots [`crate::header_size`] at construction) cannot parse.

use std::io::{Read, Write};

use crate::encrypt::{
    decrypt as low_decrypt, decrypt_triple as low_decrypt_triple,
    encrypt as low_encrypt, encrypt_triple as low_encrypt_triple,
};
use crate::error::ITBError;
use crate::ffi;
use crate::registry::{header_size, parse_chunk_len};
use crate::seed::Seed;

/// Default chunk size — matches `itb.DefaultChunkSize` on the Go side
/// (16 MB), the size at which ITB's barrier-encoded container layout
/// stays well within the per-chunk pixel cap.
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;

fn io_err(e: std::io::Error) -> ITBError {
    ITBError::with_message(ffi::STATUS_INTERNAL, format!("io: {e}"))
}

// --------------------------------------------------------------------
// Single Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Chunked encrypt writer: buffers plaintext until at least
/// `chunk_size` bytes are available, then encrypts and emits one
/// chunk to the output sink. The trailing partial buffer is flushed
/// as a final chunk on [`StreamEncryptor::close`] (so the on-the-wire
/// chunk count is `ceil(total / chunk_size)`).
///
/// Usage:
///
/// ```no_run
/// use itb::{Seed, StreamEncryptor};
///
/// let n = Seed::new("blake3", 1024).unwrap();
/// let d = Seed::new("blake3", 1024).unwrap();
/// let s = Seed::new("blake3", 1024).unwrap();
/// let mut sink: Vec<u8> = Vec::new();
/// {
///     let mut enc = StreamEncryptor::new(&n, &d, &s, &mut sink, 1 << 16).unwrap();
///     enc.write(b"chunk one").unwrap();
///     enc.write(b"chunk two").unwrap();
///     enc.close().unwrap();
/// }
/// ```
pub struct StreamEncryptor<'a, W: Write> {
    noise: &'a Seed,
    data: &'a Seed,
    start: &'a Seed,
    fout: W,
    chunk_size: usize,
    buf: Vec<u8>,
    closed: bool,
}

impl<'a, W: Write> StreamEncryptor<'a, W> {
    /// Constructs a fresh stream encryptor wrapping the given output
    /// writer. `chunk_size` must be positive.
    pub fn new(
        noise: &'a Seed,
        data: &'a Seed,
        start: &'a Seed,
        fout: W,
        chunk_size: usize,
    ) -> Result<Self, ITBError> {
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        Ok(Self {
            noise,
            data,
            start,
            fout,
            chunk_size,
            buf: Vec::new(),
            closed: false,
        })
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunk_size`-sized slice that becomes available.
    /// Returns the number of bytes consumed (always equal to
    /// `data.len()` on success).
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "write on closed StreamEncryptor",
            ));
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.chunk_size {
            // Take a copy of the prefix into chunk, then zero the
            // source range before draining so plaintext does not
            // linger in the heap region the drain slide vacates.
            let mut chunk: Vec<u8> = self.buf[..self.chunk_size].to_vec();
            for b in self.buf[..self.chunk_size].iter_mut() { *b = 0; }
            self.buf.drain(..self.chunk_size);
            let ct = low_encrypt(self.noise, self.data, self.start, &chunk)?;
            for b in chunk.iter_mut() { *b = 0; }
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        Ok(data.len())
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent — a second call is a no-op.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            let mut chunk = std::mem::take(&mut self.buf);
            let ct = low_encrypt(self.noise, self.data, self.start, &chunk)?;
            for b in chunk.iter_mut() { *b = 0; }
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamEncryptor<'a, W> {
    fn drop(&mut self) {
        // Best-effort flush; errors during drop are swallowed because
        // there is no path to surface them. Callers that need to see
        // close-time errors must call `close()` explicitly.
        let _ = self.close();
    }
}

// --------------------------------------------------------------------
// Single Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Chunked decrypt writer: accumulates ciphertext bytes via
/// [`StreamDecryptor::feed`] until a full chunk (header + body) is
/// available, then decrypts the chunk and writes the plaintext to
/// the output sink. Multiple full chunks in one feed call are
/// processed sequentially.
///
/// Usage:
///
/// ```no_run
/// use itb::{Seed, StreamDecryptor};
///
/// # let ciphertext: Vec<u8> = vec![];
/// let n = Seed::new("blake3", 1024).unwrap();
/// let d = Seed::new("blake3", 1024).unwrap();
/// let s = Seed::new("blake3", 1024).unwrap();
/// let mut sink: Vec<u8> = Vec::new();
/// {
///     let mut dec = StreamDecryptor::new(&n, &d, &s, &mut sink).unwrap();
///     dec.feed(&ciphertext).unwrap();
///     dec.close().unwrap();
/// }
/// ```
pub struct StreamDecryptor<'a, W: Write> {
    noise: &'a Seed,
    data: &'a Seed,
    start: &'a Seed,
    fout: W,
    buf: Vec<u8>,
    closed: bool,
    header_size: usize,
}

impl<'a, W: Write> StreamDecryptor<'a, W> {
    /// Constructs a fresh stream decryptor wrapping the given output
    /// writer. The chunk-header size is snapshotted at construction
    /// so the decryptor uses the same header layout the matching
    /// encryptor saw — changing [`crate::set_nonce_bits`] mid-stream
    /// would break decoding anyway.
    pub fn new(
        noise: &'a Seed,
        data: &'a Seed,
        start: &'a Seed,
        fout: W,
    ) -> Result<Self, ITBError> {
        Ok(Self {
            noise,
            data,
            start,
            fout,
            buf: Vec::new(),
            closed: false,
            header_size: header_size() as usize,
        })
    }

    /// Appends `data` to the internal buffer and drains every
    /// complete chunk that has become available, writing decrypted
    /// plaintext to the output sink.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "feed on closed StreamDecryptor",
            ));
        }
        self.buf.extend_from_slice(data);
        self.drain()?;
        Ok(data.len())
    }

    fn drain(&mut self) -> Result<(), ITBError> {
        loop {
            if self.buf.len() < self.header_size {
                return Ok(());
            }
            let chunk_len = parse_chunk_len(&self.buf[..self.header_size])?;
            if self.buf.len() < chunk_len {
                return Ok(());
            }
            let chunk: Vec<u8> = self.buf.drain(..chunk_len).collect();
            let mut pt = low_decrypt(self.noise, self.data, self.start, &chunk)?;
            self.fout.write_all(&pt).map_err(io_err)?;
            // Zero the recovered plaintext before the Vec drops.
            for b in pt.iter_mut() { *b = 0; }
        }
    }

    /// Finalises the decryptor. Errors when leftover bytes do not
    /// form a complete chunk — streaming ITB ciphertext cannot have a
    /// half-chunk tail.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                format!(
                    "StreamDecryptor: trailing {} bytes do not form a complete chunk",
                    self.buf.len()
                ),
            ));
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamDecryptor<'a, W> {
    fn drop(&mut self) {
        // Mark closed without raising on partial input — Drop has no
        // path to surface errors. Callers who need to detect a
        // half-chunk tail must call `close()` explicitly.
        self.closed = true;
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamEncryptor`].
pub struct StreamEncryptor3<'a, W: Write> {
    noise: &'a Seed,
    data1: &'a Seed,
    data2: &'a Seed,
    data3: &'a Seed,
    start1: &'a Seed,
    start2: &'a Seed,
    start3: &'a Seed,
    fout: W,
    chunk_size: usize,
    buf: Vec<u8>,
    closed: bool,
}

impl<'a, W: Write> StreamEncryptor3<'a, W> {
    /// Constructs a fresh Triple-Ouroboros stream encryptor.
    /// `chunk_size` must be positive.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        noise: &'a Seed,
        data1: &'a Seed,
        data2: &'a Seed,
        data3: &'a Seed,
        start1: &'a Seed,
        start2: &'a Seed,
        start3: &'a Seed,
        fout: W,
        chunk_size: usize,
    ) -> Result<Self, ITBError> {
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        Ok(Self {
            noise,
            data1,
            data2,
            data3,
            start1,
            start2,
            start3,
            fout,
            chunk_size,
            buf: Vec::new(),
            closed: false,
        })
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunk_size`-sized slice that becomes available.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "write on closed StreamEncryptor3",
            ));
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.chunk_size {
            let mut chunk: Vec<u8> = self.buf[..self.chunk_size].to_vec();
            for b in self.buf[..self.chunk_size].iter_mut() { *b = 0; }
            self.buf.drain(..self.chunk_size);
            let ct = low_encrypt_triple(
                self.noise,
                self.data1,
                self.data2,
                self.data3,
                self.start1,
                self.start2,
                self.start3,
                &chunk,
            )?;
            for b in chunk.iter_mut() { *b = 0; }
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        Ok(data.len())
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            let mut chunk = std::mem::take(&mut self.buf);
            let ct = low_encrypt_triple(
                self.noise,
                self.data1,
                self.data2,
                self.data3,
                self.start1,
                self.start2,
                self.start3,
                &chunk,
            )?;
            for b in chunk.iter_mut() { *b = 0; }
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamEncryptor3<'a, W> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamDecryptor`].
pub struct StreamDecryptor3<'a, W: Write> {
    noise: &'a Seed,
    data1: &'a Seed,
    data2: &'a Seed,
    data3: &'a Seed,
    start1: &'a Seed,
    start2: &'a Seed,
    start3: &'a Seed,
    fout: W,
    buf: Vec<u8>,
    closed: bool,
    header_size: usize,
}

impl<'a, W: Write> StreamDecryptor3<'a, W> {
    /// Constructs a fresh Triple-Ouroboros stream decryptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        noise: &'a Seed,
        data1: &'a Seed,
        data2: &'a Seed,
        data3: &'a Seed,
        start1: &'a Seed,
        start2: &'a Seed,
        start3: &'a Seed,
        fout: W,
    ) -> Result<Self, ITBError> {
        Ok(Self {
            noise,
            data1,
            data2,
            data3,
            start1,
            start2,
            start3,
            fout,
            buf: Vec::new(),
            closed: false,
            header_size: header_size() as usize,
        })
    }

    /// Appends `data` to the internal buffer and drains every
    /// complete chunk that has become available.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "feed on closed StreamDecryptor3",
            ));
        }
        self.buf.extend_from_slice(data);
        self.drain()?;
        Ok(data.len())
    }

    fn drain(&mut self) -> Result<(), ITBError> {
        loop {
            if self.buf.len() < self.header_size {
                return Ok(());
            }
            let chunk_len = parse_chunk_len(&self.buf[..self.header_size])?;
            if self.buf.len() < chunk_len {
                return Ok(());
            }
            let chunk: Vec<u8> = self.buf.drain(..chunk_len).collect();
            let mut pt = low_decrypt_triple(
                self.noise,
                self.data1,
                self.data2,
                self.data3,
                self.start1,
                self.start2,
                self.start3,
                &chunk,
            )?;
            self.fout.write_all(&pt).map_err(io_err)?;
            for b in pt.iter_mut() { *b = 0; }
        }
    }

    /// Finalises the decryptor. Errors when leftover bytes do not
    /// form a complete chunk.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                format!(
                    "StreamDecryptor3: trailing {} bytes do not form a complete chunk",
                    self.buf.len()
                ),
            ));
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamDecryptor3<'a, W> {
    fn drop(&mut self) {
        self.closed = true;
    }
}

// --------------------------------------------------------------------
// Functional convenience wrappers.
// --------------------------------------------------------------------

/// Reads plaintext from `fin` until EOF, encrypts in chunks of
/// `chunk_size`, and writes concatenated ITB chunks to `fout`.
pub fn encrypt_stream<R: Read, W: Write>(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mut fin: R,
    fout: W,
    chunk_size: usize,
) -> Result<(), ITBError> {
    let mut enc = StreamEncryptor::new(noise, data, start, fout, chunk_size)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        enc.write(&buf[..n])?;
    }
    let result = enc.close();
    for b in buf.iter_mut() { *b = 0; }
    result
}

/// Reads concatenated ITB chunks from `fin` until EOF and writes the
/// recovered plaintext to `fout`.
pub fn decrypt_stream<R: Read, W: Write>(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mut fin: R,
    fout: W,
    read_size: usize,
) -> Result<(), ITBError> {
    if read_size == 0 {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            "read_size must be positive",
        ));
    }
    let mut dec = StreamDecryptor::new(noise, data, start, fout)?;
    let mut buf = vec![0u8; read_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        dec.feed(&buf[..n])?;
    }
    dec.close()
}

/// Triple-Ouroboros (7-seed) counterpart of [`encrypt_stream`].
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_triple<R: Read, W: Write>(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mut fin: R,
    fout: W,
    chunk_size: usize,
) -> Result<(), ITBError> {
    let mut enc = StreamEncryptor3::new(
        noise, data1, data2, data3, start1, start2, start3, fout, chunk_size,
    )?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        enc.write(&buf[..n])?;
    }
    let result = enc.close();
    for b in buf.iter_mut() { *b = 0; }
    result
}

/// Triple-Ouroboros (7-seed) counterpart of [`decrypt_stream`].
#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream_triple<R: Read, W: Write>(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mut fin: R,
    fout: W,
    read_size: usize,
) -> Result<(), ITBError> {
    if read_size == 0 {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            "read_size must be positive",
        ));
    }
    let mut dec = StreamDecryptor3::new(
        noise, data1, data2, data3, start1, start2, start3, fout,
    )?;
    let mut buf = vec![0u8; read_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        dec.feed(&buf[..n])?;
    }
    dec.close()
}

// --------------------------------------------------------------------
// Streaming AEAD: 32-byte stream prefix + per-chunk MAC under
// (stream_id, cumulative_pixel_offset, final_flag) binding.
// --------------------------------------------------------------------
//
// The Streaming AEAD wrappers extend the plain streaming surface with
// an authentication binding tuple — `(stream_id, cumulative_pixel_offset,
// final_flag)` — that closes chunk reorder, replay within stream,
// cross-stream replay, truncate-tail, and after-final attack vectors.
//
// On wire: a 32-byte CSPRNG `stream_id` prefix is written once at
// stream start, followed by a sequence of standard ITB chunks. The
// `final_flag` byte is appended to the encrypted body inside the
// container (deniable layout; not externally visible). The
// `cumulative_pixel_offset` is recomputed by both sides from each
// chunk's on-wire `W` * `H` header, so it never appears as a wire
// field. Tampered transcript surfaces as `STATUS_MAC_FAILURE` on the
// affected chunk; missing terminator surfaces as
// `STATUS_STREAM_TRUNCATED`; trailing bytes after the terminator
// surface as `STATUS_STREAM_AFTER_FINAL`.

use std::ffi::c_void;

use crate::mac::MAC;

const STREAM_ID_LEN: usize = 32;

/// Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by
/// piggybacking on libitb's own CSPRNG: `ITB_NewSeedFromComponents`
/// with hash_key=NULL triggers a CSPRNG draw on the Go side, and
/// `ITB_GetSeedHashKey` reads back the 32-byte fixed key under the
/// blake3 primitive. The seed handle is freed before this returns;
/// only the 32 random bytes survive. Mirrors the C reference helper
/// `generate_stream_id` in `bindings/c/src/streams.c`.
fn generate_stream_id() -> Result<[u8; STREAM_ID_LEN], ITBError> {
    let lib = ffi::lib();
    let cname = std::ffi::CString::new("blake3").unwrap();
    // Eight nonzero placeholder components — values are immaterial:
    // the CSPRNG-generated hash key is what becomes the stream_id.
    let comps: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut handle: usize = 0;
    let rc = unsafe {
        (lib.ITB_NewSeedFromComponents)(
            cname.as_ptr(),
            comps.as_ptr(),
            comps.len() as std::ffi::c_int,
            std::ptr::null(),
            0,
            &mut handle,
        )
    };
    if rc != ffi::STATUS_OK {
        return Err(ITBError::with_message(rc, "stream_id seed alloc failed"));
    }
    let mut out = [0u8; STREAM_ID_LEN];
    let mut got: usize = 0;
    let rc = unsafe {
        (lib.ITB_GetSeedHashKey)(
            handle,
            out.as_mut_ptr(),
            STREAM_ID_LEN,
            &mut got,
        )
    };
    let free_rc = unsafe { (lib.ITB_FreeSeed)(handle) };
    if rc != ffi::STATUS_OK {
        return Err(ITBError::with_message(rc, "stream_id hash-key fetch failed"));
    }
    if free_rc != ffi::STATUS_OK {
        return Err(ITBError::with_message(free_rc, "stream_id seed free failed"));
    }
    if got != STREAM_ID_LEN {
        return Err(ITBError::with_message(
            ffi::STATUS_INTERNAL,
            "stream_id CSPRNG draw returned wrong byte count",
        ));
    }
    Ok(out)
}

/// Resolves the per-chunk encrypt-side ABI export for a given native
/// hash width (Single Ouroboros, 3 seeds + MAC).
fn enc_auth_single_for_width(width: i32) -> Result<ffi::FnEncryptStreamAuth, ITBError> {
    let lib = ffi::lib();
    Ok(match width {
        128 => lib.ITB_EncryptStreamAuthenticated128,
        256 => lib.ITB_EncryptStreamAuthenticated256,
        512 => lib.ITB_EncryptStreamAuthenticated512,
        _ => {
            return Err(ITBError::with_message(
                ffi::STATUS_SEED_WIDTH_MIX,
                format!("unsupported native hash width {width}"),
            ))
        }
    })
}

fn dec_auth_single_for_width(width: i32) -> Result<ffi::FnDecryptStreamAuth, ITBError> {
    let lib = ffi::lib();
    Ok(match width {
        128 => lib.ITB_DecryptStreamAuthenticated128,
        256 => lib.ITB_DecryptStreamAuthenticated256,
        512 => lib.ITB_DecryptStreamAuthenticated512,
        _ => {
            return Err(ITBError::with_message(
                ffi::STATUS_SEED_WIDTH_MIX,
                format!("unsupported native hash width {width}"),
            ))
        }
    })
}

fn enc_auth_triple_for_width(width: i32) -> Result<ffi::FnEncryptStreamAuth3, ITBError> {
    let lib = ffi::lib();
    Ok(match width {
        128 => lib.ITB_EncryptStreamAuthenticated3x128,
        256 => lib.ITB_EncryptStreamAuthenticated3x256,
        512 => lib.ITB_EncryptStreamAuthenticated3x512,
        _ => {
            return Err(ITBError::with_message(
                ffi::STATUS_SEED_WIDTH_MIX,
                format!("unsupported native hash width {width}"),
            ))
        }
    })
}

fn dec_auth_triple_for_width(width: i32) -> Result<ffi::FnDecryptStreamAuth3, ITBError> {
    let lib = ffi::lib();
    Ok(match width {
        128 => lib.ITB_DecryptStreamAuthenticated3x128,
        256 => lib.ITB_DecryptStreamAuthenticated3x256,
        512 => lib.ITB_DecryptStreamAuthenticated3x512,
        _ => {
            return Err(ITBError::with_message(
                ffi::STATUS_SEED_WIDTH_MIX,
                format!("unsupported native hash width {width}"),
            ))
        }
    })
}

/// Reads two big-endian bytes from `p` and returns them as usize.
fn read_be16(p: &[u8]) -> usize {
    ((p[0] as usize) << 8) | (p[1] as usize)
}

/// Grow-on-demand + wipe-on-grow helper for the per-stream output
/// cache. Mirrors `Encryptor::cipher_call`'s shape: zeroes the OLD
/// contents before reassigning so the previous-chunk ciphertext /
/// plaintext does not linger in heap garbage waiting for GC.
fn ensure_stream_cache(cache: &mut Vec<u8>, need: usize) {
    if cache.len() >= need {
        return;
    }
    for b in cache.iter_mut() { *b = 0; }
    *cache = vec![0u8; need];
}

/// Per-chunk encrypt dispatch (Single). Pre-allocates output capacity
/// from the 1.25× + 128 KiB upper bound (see `Encryptor::cipher_call`)
/// and falls through to a grow-and-retry on the rare under-shoot.
/// Skips the size-probe round-trip the libitb C ABI charges (the
/// cipher does the full crypto on every call regardless of out-buffer
/// capacity, then returns BUFFER_TOO_SMALL without exposing the work
/// — so probe-then-retry doubles cipher work per call).
///
/// When `cache` is provided, the per-stream buffer is reused instead
/// of allocating a fresh `Vec<u8>` per chunk (Bonus 1b in
/// .NEXTBIND.md §7.1). When `None`, falls back to the per-call
/// allocation — preserves any future call site that has no
/// stream-class cache to attach.
#[allow(clippy::too_many_arguments)]
fn emit_chunk_auth_single(
    width: i32,
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mac: &MAC,
    plaintext: &[u8],
    stream_id: &[u8; STREAM_ID_LEN],
    cum_pixels: u64,
    final_flag: bool,
    cache: Option<&mut Vec<u8>>,
) -> Result<Vec<u8>, ITBError> {
    let f = enc_auth_single_for_width(width)?;
    let payload_len = plaintext.len();
    let in_ptr: *const c_void = if payload_len == 0 {
        std::ptr::null()
    } else {
        plaintext.as_ptr() as *const c_void
    };
    let ff: std::ffi::c_int = if final_flag { 1 } else { 0 };
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut local: Vec<u8>;
    let buf: &mut Vec<u8> = match cache {
        Some(c) => {
            ensure_stream_cache(c, cap);
            c
        }
        None => {
            local = vec![0u8; cap];
            &mut local
        }
    };
    let mut out_len: usize = 0;
    let mut rc = unsafe {
        f(
            noise.handle(),
            data.handle(),
            start.handle(),
            mac.handle(),
            in_ptr,
            payload_len,
            stream_id.as_ptr(),
            cum_pixels,
            ff,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut out_len,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        ensure_stream_cache(buf, need);
        rc = unsafe {
            f(
                noise.handle(),
                data.handle(),
                start.handle(),
                mac.handle(),
                in_ptr,
                payload_len,
                stream_id.as_ptr(),
                cum_pixels,
                ff,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut out_len,
            )
        };
    }
    if rc != ffi::STATUS_OK {
        return Err(ITBError::from_status(rc));
    }
    Ok(buf[..out_len].to_vec())
}

/// Per-chunk encrypt dispatch (Triple). 1.25× + 128 KiB pre-allocate
/// + retry-once on BUFFER_TOO_SMALL; see `emit_chunk_auth_single`.
///
/// When `cache` is provided, the per-stream buffer is reused instead
/// of allocating a fresh `Vec<u8>` per chunk (Bonus 1b in
/// .NEXTBIND.md §7.1). When `None`, falls back to the per-call
/// allocation.
#[allow(clippy::too_many_arguments)]
fn emit_chunk_auth_triple(
    width: i32,
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mac: &MAC,
    plaintext: &[u8],
    stream_id: &[u8; STREAM_ID_LEN],
    cum_pixels: u64,
    final_flag: bool,
    cache: Option<&mut Vec<u8>>,
) -> Result<Vec<u8>, ITBError> {
    let f = enc_auth_triple_for_width(width)?;
    let payload_len = plaintext.len();
    let in_ptr: *const c_void = if payload_len == 0 {
        std::ptr::null()
    } else {
        plaintext.as_ptr() as *const c_void
    };
    let ff: std::ffi::c_int = if final_flag { 1 } else { 0 };
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut local: Vec<u8>;
    let buf: &mut Vec<u8> = match cache {
        Some(c) => {
            ensure_stream_cache(c, cap);
            c
        }
        None => {
            local = vec![0u8; cap];
            &mut local
        }
    };
    let mut out_len: usize = 0;
    let mut rc = unsafe {
        f(
            noise.handle(),
            data1.handle(),
            data2.handle(),
            data3.handle(),
            start1.handle(),
            start2.handle(),
            start3.handle(),
            mac.handle(),
            in_ptr,
            payload_len,
            stream_id.as_ptr(),
            cum_pixels,
            ff,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut out_len,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        ensure_stream_cache(buf, need);
        rc = unsafe {
            f(
                noise.handle(),
                data1.handle(),
                data2.handle(),
                data3.handle(),
                start1.handle(),
                start2.handle(),
                start3.handle(),
                mac.handle(),
                in_ptr,
                payload_len,
                stream_id.as_ptr(),
                cum_pixels,
                ff,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut out_len,
            )
        };
    }
    if rc != ffi::STATUS_OK {
        return Err(ITBError::from_status(rc));
    }
    Ok(buf[..out_len].to_vec())
}

/// Per-chunk decrypt dispatch (Single). Returns `(plaintext,
/// final_flag)`. 1.25× + 128 KiB pre-allocate + retry-once on
/// BUFFER_TOO_SMALL; see `emit_chunk_auth_single`. Decrypt output
/// (plaintext) is bounded above by ciphertext length, so the
/// pre-allocation is generous.
///
/// When `cache` is provided, the per-stream buffer is reused instead
/// of allocating a fresh `Vec<u8>` per chunk (Bonus 1b in
/// .NEXTBIND.md §7.1). When `None`, falls back to the per-call
/// allocation.
#[allow(clippy::too_many_arguments)]
fn consume_chunk_auth_single(
    width: i32,
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mac: &MAC,
    ciphertext: &[u8],
    stream_id: &[u8; STREAM_ID_LEN],
    cum_pixels: u64,
    cache: Option<&mut Vec<u8>>,
) -> Result<(Vec<u8>, bool), ITBError> {
    let f = dec_auth_single_for_width(width)?;
    let payload_len = ciphertext.len();
    let in_ptr: *const c_void = if payload_len == 0 {
        std::ptr::null()
    } else {
        ciphertext.as_ptr() as *const c_void
    };
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut local: Vec<u8>;
    let buf: &mut Vec<u8> = match cache {
        Some(c) => {
            ensure_stream_cache(c, cap);
            c
        }
        None => {
            local = vec![0u8; cap];
            &mut local
        }
    };
    let mut out_len: usize = 0;
    let mut ff: std::ffi::c_int = 0;
    let mut rc = unsafe {
        f(
            noise.handle(),
            data.handle(),
            start.handle(),
            mac.handle(),
            in_ptr,
            payload_len,
            stream_id.as_ptr(),
            cum_pixels,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut out_len,
            &mut ff,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        ensure_stream_cache(buf, need);
        rc = unsafe {
            f(
                noise.handle(),
                data.handle(),
                start.handle(),
                mac.handle(),
                in_ptr,
                payload_len,
                stream_id.as_ptr(),
                cum_pixels,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut out_len,
                &mut ff,
            )
        };
    }
    if rc != ffi::STATUS_OK {
        return Err(ITBError::from_status(rc));
    }
    Ok((buf[..out_len].to_vec(), ff != 0))
}

/// Per-chunk decrypt dispatch (Triple). 1.25× + 128 KiB pre-allocate
/// + retry-once on BUFFER_TOO_SMALL; see `emit_chunk_auth_single`.
///
/// When `cache` is provided, the per-stream buffer is reused instead
/// of allocating a fresh `Vec<u8>` per chunk (Bonus 1b in
/// .NEXTBIND.md §7.1). When `None`, falls back to the per-call
/// allocation.
#[allow(clippy::too_many_arguments)]
fn consume_chunk_auth_triple(
    width: i32,
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mac: &MAC,
    ciphertext: &[u8],
    stream_id: &[u8; STREAM_ID_LEN],
    cum_pixels: u64,
    cache: Option<&mut Vec<u8>>,
) -> Result<(Vec<u8>, bool), ITBError> {
    let f = dec_auth_triple_for_width(width)?;
    let payload_len = ciphertext.len();
    let in_ptr: *const c_void = if payload_len == 0 {
        std::ptr::null()
    } else {
        ciphertext.as_ptr() as *const c_void
    };
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut local: Vec<u8>;
    let buf: &mut Vec<u8> = match cache {
        Some(c) => {
            ensure_stream_cache(c, cap);
            c
        }
        None => {
            local = vec![0u8; cap];
            &mut local
        }
    };
    let mut out_len: usize = 0;
    let mut ff: std::ffi::c_int = 0;
    let mut rc = unsafe {
        f(
            noise.handle(),
            data1.handle(),
            data2.handle(),
            data3.handle(),
            start1.handle(),
            start2.handle(),
            start3.handle(),
            mac.handle(),
            in_ptr,
            payload_len,
            stream_id.as_ptr(),
            cum_pixels,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut out_len,
            &mut ff,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        ensure_stream_cache(buf, need);
        rc = unsafe {
            f(
                noise.handle(),
                data1.handle(),
                data2.handle(),
                data3.handle(),
                start1.handle(),
                start2.handle(),
                start3.handle(),
                mac.handle(),
                in_ptr,
                payload_len,
                stream_id.as_ptr(),
                cum_pixels,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut out_len,
                &mut ff,
            )
        };
    }
    if rc != ffi::STATUS_OK {
        return Err(ITBError::from_status(rc));
    }
    Ok((buf[..out_len].to_vec(), ff != 0))
}

// --------------------------------------------------------------------
// StreamEncryptorAuth — Single Ouroboros + MAC, RAII writer.
// --------------------------------------------------------------------

/// Authenticated chunked encrypt writer (Single Ouroboros + MAC).
/// Buffers plaintext until at least `chunk_size` bytes are available,
/// then drains one full chunk per FFI call. Each chunk is bound to
/// the running `(stream_id, cumulative_pixel_offset, final_flag)`
/// tuple inside the MAC closure; the 32-byte `stream_id` prefix is
/// written to the sink at stream start and the terminating chunk
/// carries `final_flag = true`.
///
/// Closed-state preflight is enforced: any `write` / `close` after
/// `close` (or after `Drop`) surfaces `STATUS_EASY_CLOSED`.
pub struct StreamEncryptorAuth<'a, W: Write> {
    noise: &'a Seed,
    data: &'a Seed,
    start: &'a Seed,
    mac: &'a MAC,
    fout: W,
    chunk_size: usize,
    width: i32,
    stream_id: [u8; STREAM_ID_LEN],
    header_size: usize,
    cum_pixels: u64,
    buf: Vec<u8>,
    closed: bool,
    prefix_emitted: bool,
    /// Per-stream output buffer cache. Grows on demand; `close` /
    /// `Drop` wipe it before drop. Same Bonus 1b shape as the
    /// per-encryptor cache on `Encryptor` — the streaming class owns
    /// its own cache because the helper free functions have no
    /// encryptor instance to attach to (.NEXTBIND.md §7.1).
    out_buf: Vec<u8>,
}

impl<'a, W: Write> StreamEncryptorAuth<'a, W> {
    /// Constructs a fresh authenticated stream encryptor wrapping the
    /// given output writer. `chunk_size` must be positive. The
    /// 32-byte CSPRNG `stream_id` prefix is generated inside the
    /// constructor and emitted on the first `write` / `close` call;
    /// the prefix is not visible to the caller.
    pub fn new(
        noise: &'a Seed,
        data: &'a Seed,
        start: &'a Seed,
        mac: &'a MAC,
        fout: W,
        chunk_size: usize,
    ) -> Result<Self, ITBError> {
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        let width = noise.width()?;
        let stream_id = generate_stream_id()?;
        Ok(Self {
            noise,
            data,
            start,
            mac,
            fout,
            chunk_size,
            width,
            stream_id,
            header_size: header_size() as usize,
            cum_pixels: 0,
            buf: Vec::new(),
            closed: false,
            prefix_emitted: false,
            out_buf: Vec::new(),
        })
    }

    fn emit_prefix(&mut self) -> Result<(), ITBError> {
        if !self.prefix_emitted {
            self.fout.write_all(&self.stream_id).map_err(io_err)?;
            self.prefix_emitted = true;
        }
        Ok(())
    }

    /// Zeroes and drops the per-stream output cache. Called from
    /// `close` and `Drop` so the last chunk's ciphertext does not
    /// linger in heap memory after the stream finalises.
    fn wipe_out_buf(&mut self) {
        for b in self.out_buf.iter_mut() { *b = 0; }
        self.out_buf.clear();
    }

    /// Emits one chunk of `plaintext_len` bytes from the buffer,
    /// advancing `cum_pixels` from the on-wire `W` * `H` header of
    /// the produced ciphertext.
    fn emit_one(&mut self, plaintext_len: usize, final_flag: bool) -> Result<(), ITBError> {
        let chunk_pt: Vec<u8> = self.buf.drain(..plaintext_len).collect();
        let ct = emit_chunk_auth_single(
            self.width,
            self.noise,
            self.data,
            self.start,
            self.mac,
            &chunk_pt,
            &self.stream_id,
            self.cum_pixels,
            final_flag,
            Some(&mut self.out_buf),
        )?;
        // Wipe the per-chunk plaintext copy before drop.
        let mut chunk_pt = chunk_pt;
        for b in chunk_pt.iter_mut() { *b = 0; }
        if ct.len() >= self.header_size {
            let w = read_be16(&ct[self.header_size - 4..self.header_size - 2]);
            let h = read_be16(&ct[self.header_size - 2..self.header_size]);
            self.cum_pixels += (w as u64) * (h as u64);
        }
        self.fout.write_all(&ct).map_err(io_err)?;
        Ok(())
    }

    /// Appends `data` to the internal buffer. Drains every
    /// completed-but-not-final chunk to the sink. The terminating
    /// chunk is emitted only by [`StreamEncryptorAuth::close`] —
    /// `final_flag = true` cannot be set until end-of-input is
    /// signalled, so any chunk emitted from inside `write` carries
    /// `final_flag = false`.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "write on closed StreamEncryptorAuth",
            ));
        }
        self.emit_prefix()?;
        self.buf.extend_from_slice(data);
        // Drain non-terminal chunks: keep at least one chunk worth
        // buffered until close() time so the deferred-final pattern
        // can decide whether to emit final_flag = true.
        while self.buf.len() > self.chunk_size {
            self.emit_one(self.chunk_size, false)?;
        }
        Ok(data.len())
    }

    /// Emits the residual buffer as the terminating chunk and
    /// finalises the stream. Idempotent — a second call is a no-op.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        self.emit_prefix()?;
        let remaining = self.buf.len();
        // Emit pending non-terminal chunks if buf overflowed exactly.
        // After the loop in write(), buf <= chunk_size remaining.
        // Empty stream still emits one terminating chunk with len 0.
        self.emit_one(remaining, true)?;
        self.closed = true;
        self.wipe_out_buf();
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamEncryptorAuth<'a, W> {
    fn drop(&mut self) {
        let _ = self.close();
        // close() wipes on the success path; cover the early-return /
        // error path here so the cache never escapes Drop populated.
        self.wipe_out_buf();
    }
}

// --------------------------------------------------------------------
// StreamDecryptorAuth — Single Ouroboros + MAC, RAII reader.
// --------------------------------------------------------------------

/// Authenticated chunked decrypt writer (Single Ouroboros + MAC).
/// Reads the 32-byte `stream_id` prefix once, then drains every
/// complete chunk available in the internal buffer. Each chunk is
/// verified under the running cumulative pixel offset and recovered
/// final_flag; missing terminator surfaces as
/// [`ffi::STATUS_STREAM_TRUNCATED`] from `close`, trailing bytes
/// after the terminator surface as
/// [`ffi::STATUS_STREAM_AFTER_FINAL`] on the next `feed` / `close`.
pub struct StreamDecryptorAuth<'a, W: Write> {
    noise: &'a Seed,
    data: &'a Seed,
    start: &'a Seed,
    mac: &'a MAC,
    fout: W,
    width: i32,
    header_size: usize,
    stream_id: [u8; STREAM_ID_LEN],
    sid_have: usize,
    cum_pixels: u64,
    buf: Vec<u8>,
    seen_final: bool,
    closed: bool,
    /// Per-stream output buffer cache. Same Bonus 1b shape as the
    /// encrypt-side counterpart; reused across every chunk's decrypt
    /// dispatch instead of a fresh `Vec<u8>` per chunk
    /// (.NEXTBIND.md §7.1).
    out_buf: Vec<u8>,
}

impl<'a, W: Write> StreamDecryptorAuth<'a, W> {
    /// Constructs a fresh authenticated stream decryptor wrapping the
    /// given output writer. The 32-byte `stream_id` prefix is read
    /// from the first 32 bytes fed via `feed`.
    pub fn new(
        noise: &'a Seed,
        data: &'a Seed,
        start: &'a Seed,
        mac: &'a MAC,
        fout: W,
    ) -> Result<Self, ITBError> {
        let width = noise.width()?;
        Ok(Self {
            noise,
            data,
            start,
            mac,
            fout,
            width,
            header_size: header_size() as usize,
            stream_id: [0u8; STREAM_ID_LEN],
            sid_have: 0,
            cum_pixels: 0,
            buf: Vec::new(),
            seen_final: false,
            closed: false,
            out_buf: Vec::new(),
        })
    }

    /// Zeroes and drops the per-stream output cache. Called from
    /// `close` and `Drop` so the last chunk's plaintext does not
    /// linger in heap memory after the stream finalises.
    fn wipe_out_buf(&mut self) {
        for b in self.out_buf.iter_mut() { *b = 0; }
        self.out_buf.clear();
    }

    fn drain(&mut self) -> Result<(), ITBError> {
        loop {
            if self.seen_final {
                if !self.buf.is_empty() {
                    return Err(ITBError::with_message(
                        ffi::STATUS_STREAM_AFTER_FINAL,
                        "auth stream: trailing bytes after terminator",
                    ));
                }
                return Ok(());
            }
            if self.buf.len() < self.header_size {
                return Ok(());
            }
            let chunk_len = parse_chunk_len(&self.buf[..self.header_size])?;
            if self.buf.len() < chunk_len {
                return Ok(());
            }
            let w = read_be16(&self.buf[self.header_size - 4..self.header_size - 2]);
            let h = read_be16(&self.buf[self.header_size - 2..self.header_size]);
            let pixels = (w as u64) * (h as u64);
            let chunk: Vec<u8> = self.buf.drain(..chunk_len).collect();
            let (mut pt, ff) = consume_chunk_auth_single(
                self.width,
                self.noise,
                self.data,
                self.start,
                self.mac,
                &chunk,
                &self.stream_id,
                self.cum_pixels,
                Some(&mut self.out_buf),
            )?;
            self.fout.write_all(&pt).map_err(io_err)?;
            for b in pt.iter_mut() { *b = 0; }
            self.cum_pixels += pixels;
            if ff {
                self.seen_final = true;
            }
        }
    }

    /// Appends `data` to the internal buffer and drains every
    /// complete chunk available. Surfaces a typed error on tampered
    /// transcript or trailing bytes after the terminator.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "feed on closed StreamDecryptorAuth",
            ));
        }
        let mut off = 0usize;
        if self.sid_have < STREAM_ID_LEN {
            let need = STREAM_ID_LEN - self.sid_have;
            let take = std::cmp::min(need, data.len());
            self.stream_id[self.sid_have..self.sid_have + take]
                .copy_from_slice(&data[..take]);
            self.sid_have += take;
            off = take;
        }
        if off < data.len() {
            self.buf.extend_from_slice(&data[off..]);
        }
        if self.sid_have == STREAM_ID_LEN {
            self.drain()?;
        }
        Ok(data.len())
    }

    /// Finalises the decryptor. Surfaces
    /// [`ffi::STATUS_STREAM_TRUNCATED`] when no terminating chunk has
    /// been observed, or
    /// [`ffi::STATUS_STREAM_AFTER_FINAL`] when extra bytes follow a
    /// terminator. Idempotent.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if self.sid_have < STREAM_ID_LEN {
            self.closed = true;
            self.wipe_out_buf();
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "auth stream: 32-byte stream prefix incomplete",
            ));
        }
        // Drain any remaining buffered chunks.
        self.drain()?;
        self.closed = true;
        self.wipe_out_buf();
        if !self.seen_final {
            return Err(ITBError::with_message(
                ffi::STATUS_STREAM_TRUNCATED,
                "auth stream: terminator never observed",
            ));
        }
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamDecryptorAuth<'a, W> {
    fn drop(&mut self) {
        // Mark closed; surface no error here — Drop has no path to
        // raise. Callers that need to detect truncation must call
        // close() explicitly.
        self.closed = true;
        self.wipe_out_buf();
    }
}

// --------------------------------------------------------------------
// StreamEncryptorAuth3 / StreamDecryptorAuth3 — Triple Ouroboros + MAC.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`StreamEncryptorAuth`].
pub struct StreamEncryptorAuth3<'a, W: Write> {
    noise: &'a Seed,
    data1: &'a Seed,
    data2: &'a Seed,
    data3: &'a Seed,
    start1: &'a Seed,
    start2: &'a Seed,
    start3: &'a Seed,
    mac: &'a MAC,
    fout: W,
    chunk_size: usize,
    width: i32,
    stream_id: [u8; STREAM_ID_LEN],
    header_size: usize,
    cum_pixels: u64,
    buf: Vec<u8>,
    closed: bool,
    prefix_emitted: bool,
    /// Per-stream output buffer cache. Same Bonus 1b shape as
    /// `StreamEncryptorAuth.out_buf`; reused across every chunk's
    /// encrypt dispatch (.NEXTBIND.md §7.1).
    out_buf: Vec<u8>,
}

impl<'a, W: Write> StreamEncryptorAuth3<'a, W> {
    /// Constructs a fresh Triple-Ouroboros authenticated stream
    /// encryptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        noise: &'a Seed,
        data1: &'a Seed,
        data2: &'a Seed,
        data3: &'a Seed,
        start1: &'a Seed,
        start2: &'a Seed,
        start3: &'a Seed,
        mac: &'a MAC,
        fout: W,
        chunk_size: usize,
    ) -> Result<Self, ITBError> {
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        let width = noise.width()?;
        let stream_id = generate_stream_id()?;
        Ok(Self {
            noise,
            data1,
            data2,
            data3,
            start1,
            start2,
            start3,
            mac,
            fout,
            chunk_size,
            width,
            stream_id,
            header_size: header_size() as usize,
            cum_pixels: 0,
            buf: Vec::new(),
            closed: false,
            prefix_emitted: false,
            out_buf: Vec::new(),
        })
    }

    fn emit_prefix(&mut self) -> Result<(), ITBError> {
        if !self.prefix_emitted {
            self.fout.write_all(&self.stream_id).map_err(io_err)?;
            self.prefix_emitted = true;
        }
        Ok(())
    }

    /// Zeroes and drops the per-stream output cache. Called from
    /// `close` and `Drop` so the last chunk's ciphertext does not
    /// linger in heap memory after the stream finalises.
    fn wipe_out_buf(&mut self) {
        for b in self.out_buf.iter_mut() { *b = 0; }
        self.out_buf.clear();
    }

    fn emit_one(&mut self, plaintext_len: usize, final_flag: bool) -> Result<(), ITBError> {
        let chunk_pt: Vec<u8> = self.buf.drain(..plaintext_len).collect();
        let ct = emit_chunk_auth_triple(
            self.width,
            self.noise,
            self.data1,
            self.data2,
            self.data3,
            self.start1,
            self.start2,
            self.start3,
            self.mac,
            &chunk_pt,
            &self.stream_id,
            self.cum_pixels,
            final_flag,
            Some(&mut self.out_buf),
        )?;
        let mut chunk_pt = chunk_pt;
        for b in chunk_pt.iter_mut() { *b = 0; }
        if ct.len() >= self.header_size {
            let w = read_be16(&ct[self.header_size - 4..self.header_size - 2]);
            let h = read_be16(&ct[self.header_size - 2..self.header_size]);
            self.cum_pixels += (w as u64) * (h as u64);
        }
        self.fout.write_all(&ct).map_err(io_err)?;
        Ok(())
    }

    /// Appends `data` to the internal buffer.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "write on closed StreamEncryptorAuth3",
            ));
        }
        self.emit_prefix()?;
        self.buf.extend_from_slice(data);
        while self.buf.len() > self.chunk_size {
            self.emit_one(self.chunk_size, false)?;
        }
        Ok(data.len())
    }

    /// Emits the residual buffer as the terminating chunk.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        self.emit_prefix()?;
        let remaining = self.buf.len();
        self.emit_one(remaining, true)?;
        self.closed = true;
        self.wipe_out_buf();
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamEncryptorAuth3<'a, W> {
    fn drop(&mut self) {
        let _ = self.close();
        // close() wipes on the success path; cover the early-return /
        // error path here so the cache never escapes Drop populated.
        self.wipe_out_buf();
    }
}

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`StreamDecryptorAuth`].
pub struct StreamDecryptorAuth3<'a, W: Write> {
    noise: &'a Seed,
    data1: &'a Seed,
    data2: &'a Seed,
    data3: &'a Seed,
    start1: &'a Seed,
    start2: &'a Seed,
    start3: &'a Seed,
    mac: &'a MAC,
    fout: W,
    width: i32,
    header_size: usize,
    stream_id: [u8; STREAM_ID_LEN],
    sid_have: usize,
    cum_pixels: u64,
    buf: Vec<u8>,
    seen_final: bool,
    closed: bool,
    /// Per-stream output buffer cache. Same Bonus 1b shape as
    /// `StreamDecryptorAuth.out_buf`; reused across every chunk's
    /// decrypt dispatch (.NEXTBIND.md §7.1).
    out_buf: Vec<u8>,
}

impl<'a, W: Write> StreamDecryptorAuth3<'a, W> {
    /// Constructs a fresh Triple-Ouroboros authenticated stream
    /// decryptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        noise: &'a Seed,
        data1: &'a Seed,
        data2: &'a Seed,
        data3: &'a Seed,
        start1: &'a Seed,
        start2: &'a Seed,
        start3: &'a Seed,
        mac: &'a MAC,
        fout: W,
    ) -> Result<Self, ITBError> {
        let width = noise.width()?;
        Ok(Self {
            noise,
            data1,
            data2,
            data3,
            start1,
            start2,
            start3,
            mac,
            fout,
            width,
            header_size: header_size() as usize,
            stream_id: [0u8; STREAM_ID_LEN],
            sid_have: 0,
            cum_pixels: 0,
            buf: Vec::new(),
            seen_final: false,
            closed: false,
            out_buf: Vec::new(),
        })
    }

    /// Zeroes and drops the per-stream output cache. Called from
    /// `close` and `Drop` so the last chunk's plaintext does not
    /// linger in heap memory after the stream finalises.
    fn wipe_out_buf(&mut self) {
        for b in self.out_buf.iter_mut() { *b = 0; }
        self.out_buf.clear();
    }

    fn drain(&mut self) -> Result<(), ITBError> {
        loop {
            if self.seen_final {
                if !self.buf.is_empty() {
                    return Err(ITBError::with_message(
                        ffi::STATUS_STREAM_AFTER_FINAL,
                        "auth stream: trailing bytes after terminator",
                    ));
                }
                return Ok(());
            }
            if self.buf.len() < self.header_size {
                return Ok(());
            }
            let chunk_len = parse_chunk_len(&self.buf[..self.header_size])?;
            if self.buf.len() < chunk_len {
                return Ok(());
            }
            let w = read_be16(&self.buf[self.header_size - 4..self.header_size - 2]);
            let h = read_be16(&self.buf[self.header_size - 2..self.header_size]);
            let pixels = (w as u64) * (h as u64);
            let chunk: Vec<u8> = self.buf.drain(..chunk_len).collect();
            let (mut pt, ff) = consume_chunk_auth_triple(
                self.width,
                self.noise,
                self.data1,
                self.data2,
                self.data3,
                self.start1,
                self.start2,
                self.start3,
                self.mac,
                &chunk,
                &self.stream_id,
                self.cum_pixels,
                Some(&mut self.out_buf),
            )?;
            self.fout.write_all(&pt).map_err(io_err)?;
            for b in pt.iter_mut() { *b = 0; }
            self.cum_pixels += pixels;
            if ff {
                self.seen_final = true;
            }
        }
    }

    /// Appends `data` to the internal buffer.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "feed on closed StreamDecryptorAuth3",
            ));
        }
        let mut off = 0usize;
        if self.sid_have < STREAM_ID_LEN {
            let need = STREAM_ID_LEN - self.sid_have;
            let take = std::cmp::min(need, data.len());
            self.stream_id[self.sid_have..self.sid_have + take]
                .copy_from_slice(&data[..take]);
            self.sid_have += take;
            off = take;
        }
        if off < data.len() {
            self.buf.extend_from_slice(&data[off..]);
        }
        if self.sid_have == STREAM_ID_LEN {
            self.drain()?;
        }
        Ok(data.len())
    }

    /// Finalises the decryptor.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if self.sid_have < STREAM_ID_LEN {
            self.closed = true;
            self.wipe_out_buf();
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "auth stream: 32-byte stream prefix incomplete",
            ));
        }
        self.drain()?;
        self.closed = true;
        self.wipe_out_buf();
        if !self.seen_final {
            return Err(ITBError::with_message(
                ffi::STATUS_STREAM_TRUNCATED,
                "auth stream: terminator never observed",
            ));
        }
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamDecryptorAuth3<'a, W> {
    fn drop(&mut self) {
        self.closed = true;
        self.wipe_out_buf();
    }
}

// --------------------------------------------------------------------
// Free-function authenticated stream helpers.
// --------------------------------------------------------------------

/// Reads plaintext from `fin` until EOF, encrypts in chunks of
/// `chunk_size` under Single-Ouroboros + MAC, and writes the
/// 32-byte stream prefix followed by concatenated authenticated
/// chunks to `fout`.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_auth<R: Read, W: Write>(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mac: &MAC,
    mut fin: R,
    fout: W,
    chunk_size: usize,
) -> Result<(), ITBError> {
    let mut enc = StreamEncryptorAuth::new(noise, data, start, mac, fout, chunk_size)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        enc.write(&buf[..n])?;
    }
    let result = enc.close();
    for b in buf.iter_mut() { *b = 0; }
    result
}

/// Reads an authenticated stream transcript from `fin` and writes the
/// recovered plaintext to `fout`. Surfaces
/// [`ffi::STATUS_STREAM_TRUNCATED`] / [`ffi::STATUS_STREAM_AFTER_FINAL`]
/// on the two end-of-stream failure modes;
/// [`ffi::STATUS_MAC_FAILURE`] surfaces verbatim from the per-chunk
/// path on tampered transcript.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream_auth<R: Read, W: Write>(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mac: &MAC,
    mut fin: R,
    fout: W,
    read_size: usize,
) -> Result<(), ITBError> {
    if read_size == 0 {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            "read_size must be positive",
        ));
    }
    let mut dec = StreamDecryptorAuth::new(noise, data, start, mac, fout)?;
    let mut buf = vec![0u8; read_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        dec.feed(&buf[..n])?;
    }
    dec.close()
}

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`encrypt_stream_auth`].
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_auth_triple<R: Read, W: Write>(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mac: &MAC,
    mut fin: R,
    fout: W,
    chunk_size: usize,
) -> Result<(), ITBError> {
    let mut enc = StreamEncryptorAuth3::new(
        noise, data1, data2, data3, start1, start2, start3, mac, fout, chunk_size,
    )?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        enc.write(&buf[..n])?;
    }
    let result = enc.close();
    for b in buf.iter_mut() { *b = 0; }
    result
}

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`decrypt_stream_auth`].
#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream_auth_triple<R: Read, W: Write>(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mac: &MAC,
    mut fin: R,
    fout: W,
    read_size: usize,
) -> Result<(), ITBError> {
    if read_size == 0 {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            "read_size must be positive",
        ));
    }
    let mut dec = StreamDecryptorAuth3::new(
        noise, data1, data2, data3, start1, start2, start3, mac, fout,
    )?;
    let mut buf = vec![0u8; read_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        dec.feed(&buf[..n])?;
    }
    dec.close()
}
