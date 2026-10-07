//! Long-run stress harness. The loop utility holds one Pipeline handle
//! per exercised cipher surface for minutes, hammers it with
//! concurrent encrypt → decrypt → compare round-trips from N worker
//! threads, rotates the outer masters and reopens the handle from its
//! session blob on a schedule, and reports whether the process
//! survived with every byte intact. It is the Rust binding's
//! counterpart of the Go harness under tools/loop: the same flags, the
//! same round structure, the same summary in both renderings.
//!
//! The default shape is full production: the Streaming AEAD profile
//! with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
//! inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
//! driven through a stream session by three workers for five minutes
//! on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
//! plaintext held for the whole run, so any cross-call state leakage
//! inside the Pipeline surfaces as a data mismatch between workers
//! rather than cancelling out.
//!
//! A failure is one of two things. A cipher, rekey or load call that
//! returns a non-OK status is a worker error: the run stops, the
//! summary lists it, the verdict is FAIL and the exit code 1. A
//! round-trip that returns without error but with different bytes is
//! a data mismatch: the process terminates on the spot with exit
//! code 3, printing the worker, the iteration and the first differing
//! offset, and no summary — the state that produced the wrong bytes
//! is the evidence. A crash inside the shared library or the host
//! runtime has no exit code of its own here; surfacing it is what the
//! utility is for.
//!
//! Usage:
//!
//!   ./target/release/loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
//!          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
//!          --parallax on --wrapper on
//!
//! Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
//! then the partial summary prints.

mod ops;
mod payload;
mod size;
mod summary;
mod worker;

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Barrier, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use itb3::{OptsBuilder, Pipeline};

use payload::{PayloadMode, fill_payload, seed_worker};
use size::{human_bytes, human_duration, parse_duration, parse_size, round_to};
use worker::Shape;

/// --goroutines ceiling; the harness targets modest hosts and each
/// worker pins payload-sized buffers for the whole run.
pub const MAX_WORKERS: usize = 10;

/// The concurrency mode this binding implements, as the summary
/// reports it (shared-handle / independent-handles / single).
pub const CONCURRENCY: &str = "shared-handle";

/// Largest slice fed to a stream session per write; the drain after
/// every write uses the same bound.
pub const PUMP_SLICE: usize = 1 << 20;

/// Profiles the shape-based pair is built against when --profile is
/// empty.
const DEFAULT_STREAM_PROFILE: &str = "streaming-aead-triple-mac-v1";
const DEFAULT_MESSAGE_PROFILE: &str = "singlemsg-triple-mac-v1";

/// The keystream-capable primitive supplied for a layer a profile
/// leaves unnamed: PRF-grade, so sound outside the barrier, and the
/// closest relative of the AES-based inner primitive whose profiles
/// need the fill.
const KEYSTREAM_FILL_CIPHER: &str = "aescmac";

/// The parallax segment size a filled palette runs with — the
/// library's own default; a schedule rejects zero.
const KEYSTREAM_FILL_SEGMENT: i64 = 4093;

/// The resolved command line.
pub struct Config {
    pub duration_ns: i64,
    pub iterations: i64,
    pub workers_requested: usize,
    pub workers: usize,
    pub shape: Shape,
    pub hash: String,
    pub mac: String,
    pub payload: i64,
    pub memlimit: i64,
    pub memlimit_auto: bool,
    pub gogc: i32,
    pub parallax: bool,
    pub wrapper: bool,
    pub profile: String,
    pub key_bits: i64,
    pub nonce_bits: i64,
    pub blob_mode: i64,
    pub chunk_size: i64,
    pub barrier_fill: i64,
    pub drbg: String,
    pub gomaxprocs: i32,
    pub rekey_every: i64,
    pub blob_cycle_every: i64,
    pub payload_mode: PayloadMode,
    pub seed: u64,
    pub json_output: bool,
    pub memprofile: String,
}

/// The Pipeline handles and their retained blobs, behind the lock
/// that keeps iterations clear of handle mutation.
pub struct Pipes {
    pub stream: Option<Pipeline>,
    pub msg: Option<Pipeline>,
    /// The blob Init handed out, replaced by every rekey; the input of
    /// the next blob reopen.
    pub stream_blob: Vec<u8>,
    pub msg_blob: Vec<u8>,
}

/// One worker's counters, read by the summary after every worker has
/// returned, and the error it stopped on.
#[derive(Default)]
pub struct Counters {
    pub iters: AtomicI64,
    pub bytes_enc: AtomicI64,
    pub bytes_dec: AtomicI64,
    pub nanos_enc: AtomicI64,
    pub nanos_dec: AtomicI64,
    pub error: Mutex<Option<String>>,
}

/// One worker's private state, owned by its thread: its plaintext,
/// its reusable pump accumulators, its generator.
pub struct WorkerState {
    pub id: usize,
    pub plaintext: Vec<u8>,
    pub payload_mode: PayloadMode,
    pub seeded: bool,
    pub rng: u64,
    pub wire: Vec<u8>,
    pub plain: Vec<u8>,
}

/// Main waits on `done_cv` for `active` to reach zero; the last
/// returning worker stamps `finish` so elapsed excludes the wake-up
/// latency of the waiter.
pub struct Done {
    pub active: usize,
    pub finish: Option<Instant>,
}

/// The state every worker shares.
pub struct RunState {
    pub cfg: Config,
    pub stream_profile: String,
    pub msg_profile: String,
    /// Handle mutation. Iterations hold the read side for their whole
    /// encrypt → decrypt → compare; rekey and blob reopen take the
    /// write side, so no cipher call is in flight while a handle's
    /// keying changes or the handle itself is swapped, and no encrypt
    /// is separated from its decrypt by either.
    pub pipes: RwLock<Pipes>,
    pub rekeys: AtomicI64,
    pub blob_cycles: AtomicI64,
    pub workers: Vec<Counters>,
    /// Warmup barrier: workers arrive at `warmup_done` after iteration
    /// 0 and at `release` once main has taken the baselines.
    pub warmup_done: Barrier,
    pub release: Barrier,
    /// Set by the duration timer, by a signal, or by a failing worker;
    /// checked by every worker before it starts an iteration.
    pub stop: AtomicBool,
    pub done: Mutex<Done>,
    pub done_cv: Condvar,
    pub rss_warmup: u64,
    pub rss_peak: u64,
    pub rss_final: u64,
    pub pool_warmup: Vec<i64>,
    pub pool_steady: Vec<i64>,
}

/// Prints one prefixed status line to stdout.
pub fn log_line(line: &str) {
    println!("[loop] {line}");
}

pub fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// Renders an encoder policy env value for the summary: the raw string
/// when set, "default" when the shipped ladder applies.
pub fn policy_label(env: Option<String>) -> String {
    match env {
        Some(v) if !v.trim().is_empty() => v.trim_start().to_string(),
        _ => "default".to_string(),
    }
}

// ------------------------------------------------------------------
// Flags
// ------------------------------------------------------------------

/// The raw flag values before validation.
struct RawFlags {
    barrier_fill: i64,
    blob_cycle_every: i64,
    blob_mode: i64,
    chunk_size: String,
    drbg: String,
    duration: String,
    gogc: i64,
    gomaxprocs: i64,
    goroutines: i64,
    hash: String,
    iterations: i64,
    json_output: bool,
    key_bits: i64,
    mac: String,
    memlimit: String,
    memprofile: String,
    nonce_bits: i64,
    parallax: String,
    payload_mode: String,
    payload_size: String,
    profile: String,
    rekey_every: i64,
    seed: u64,
    shape: String,
    wrapper: String,
}

impl Default for RawFlags {
    fn default() -> Self {
        Self {
            barrier_fill: 0,
            blob_cycle_every: 0,
            blob_mode: 1,
            chunk_size: "0".into(),
            drbg: String::new(),
            duration: "5m".into(),
            gogc: 0,
            gomaxprocs: 0,
            goroutines: 3,
            hash: "areion512".into(),
            iterations: 0,
            json_output: false,
            key_bits: 0,
            mac: "hmac-blake3".into(),
            memlimit: "auto".into(),
            memprofile: String::new(),
            nonce_bits: 0,
            parallax: "on".into(),
            payload_mode: "fixed".into(),
            payload_size: "16MB".into(),
            profile: String::new(),
            rekey_every: 0,
            seed: 0,
            shape: "stream".into(),
            wrapper: "on".into(),
        }
    }
}

/// What a flag's value is parsed into and where it lands.
enum Slot {
    Int(fn(&mut RawFlags) -> &mut i64),
    Uint(fn(&mut RawFlags) -> &mut u64),
    Str(fn(&mut RawFlags) -> &mut String),
    Bool(fn(&mut RawFlags) -> &mut bool),
}

/// One command-line flag: its name, the type label the usage prints,
/// its help text, and its slot. Values are validated after the whole
/// line is parsed. The table is in alphabetical order (the order the
/// usage prints); `default_int` marks an int whose non-zero default
/// the usage shows, mirroring the reference's rendering.
struct Flag {
    name: &'static str,
    type_label: &'static str,
    help: &'static str,
    slot: Slot,
    show_default: bool,
}

const FLAGS: [Flag; 25] = [
    Flag {
        name: "barrier-fill",
        type_label: "int",
        help: "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)",
        slot: Slot::Int(|f| &mut f.barrier_fill),
        show_default: true,
    },
    Flag {
        name: "blob-cycle-every",
        type_label: "int",
        help: "reopen each pipeline from its session blob every N iterations per worker; 0 = never",
        slot: Slot::Int(|f| &mut f.blob_cycle_every),
        show_default: false,
    },
    Flag {
        name: "blob-mode",
        type_label: "int",
        help: "container floor sizing mode: 1 (per-region, default) | 2 (per-container)",
        slot: Slot::Int(|f| &mut f.blob_mode),
        show_default: true,
    },
    Flag {
        name: "chunk-size",
        type_label: "string",
        help: "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape",
        slot: Slot::Str(|f| &mut f.chunk_size),
        show_default: true,
    },
    Flag {
        name: "drbg",
        type_label: "string",
        help: "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)",
        slot: Slot::Str(|f| &mut f.drbg),
        show_default: true,
    },
    Flag {
        name: "duration",
        type_label: "duration",
        help: "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0",
        slot: Slot::Str(|f| &mut f.duration),
        show_default: true,
    },
    Flag {
        name: "gogc",
        type_label: "int",
        help: "GC trigger percentage; 0 = leave the runtime default",
        slot: Slot::Int(|f| &mut f.gogc),
        show_default: true,
    },
    Flag {
        name: "gomaxprocs",
        type_label: "int",
        help: "Go runtime GOMAXPROCS override; 0 = inherit from the environment",
        slot: Slot::Int(|f| &mut f.gomaxprocs),
        show_default: true,
    },
    Flag {
        name: "goroutines",
        type_label: "int",
        help: "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1",
        slot: Slot::Int(|f| &mut f.goroutines),
        show_default: true,
    },
    Flag {
        name: "hash",
        type_label: "string",
        help: "inner ITB hash primitive name",
        slot: Slot::Str(|f| &mut f.hash),
        show_default: true,
    },
    Flag {
        name: "iterations",
        type_label: "int",
        help: "fixed per-worker iteration count; 0 = duration-based",
        slot: Slot::Int(|f| &mut f.iterations),
        show_default: false,
    },
    Flag {
        name: "json-output",
        type_label: "",
        help: "print the final summary as one compact JSON object instead of log lines",
        slot: Slot::Bool(|f| &mut f.json_output),
        show_default: false,
    },
    Flag {
        name: "key-bits",
        type_label: "int",
        help: "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)",
        slot: Slot::Int(|f| &mut f.key_bits),
        show_default: true,
    },
    Flag {
        name: "mac",
        type_label: "string",
        help: "MAC primitive name",
        slot: Slot::Str(|f| &mut f.mac),
        show_default: true,
    },
    Flag {
        name: "memlimit",
        type_label: "string",
        help: "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)",
        slot: Slot::Str(|f| &mut f.memlimit),
        show_default: true,
    },
    Flag {
        name: "memprofile",
        type_label: "string",
        help: "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none",
        slot: Slot::Str(|f| &mut f.memprofile),
        show_default: true,
    },
    Flag {
        name: "nonce-bits",
        type_label: "int",
        help: "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)",
        slot: Slot::Int(|f| &mut f.nonce_bits),
        show_default: true,
    },
    Flag {
        name: "parallax",
        type_label: "string",
        help: "parallax layer: on | off",
        slot: Slot::Str(|f| &mut f.parallax),
        show_default: true,
    },
    Flag {
        name: "payload-mode",
        type_label: "string",
        help: "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii",
        slot: Slot::Str(|f| &mut f.payload_mode),
        show_default: true,
    },
    Flag {
        name: "payload-size",
        type_label: "string",
        help: "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)",
        slot: Slot::Str(|f| &mut f.payload_size),
        show_default: true,
    },
    Flag {
        name: "profile",
        type_label: "string",
        help: "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair",
        slot: Slot::Str(|f| &mut f.profile),
        show_default: true,
    },
    Flag {
        name: "rekey-every",
        type_label: "int",
        help: "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never",
        slot: Slot::Int(|f| &mut f.rekey_every),
        show_default: false,
    },
    Flag {
        name: "seed",
        type_label: "uint",
        help: "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts",
        slot: Slot::Uint(|f| &mut f.seed),
        show_default: false,
    },
    Flag {
        name: "shape",
        type_label: "string",
        help: "cipher surface to exercise: stream | message | stream_one_shot | both",
        slot: Slot::Str(|f| &mut f.shape),
        show_default: true,
    },
    Flag {
        name: "wrapper",
        type_label: "string",
        help: "wrapper layer: on | off",
        slot: Slot::Str(|f| &mut f.wrapper),
        show_default: true,
    },
];

fn usage() {
    let mut defaults = RawFlags::default();
    eprintln!("Usage of loop:");
    for fl in &FLAGS {
        if fl.type_label.is_empty() {
            eprintln!("  -{}", fl.name);
        } else {
            eprintln!("  -{} {}", fl.name, fl.type_label);
        }
        let mut line = format!("    \t{}", fl.help);
        // Rust-specific. The default-value suffix is composed by hand;
        // a flag library that appends its own renders it itself.
        if fl.show_default {
            match &fl.slot {
                Slot::Int(get) => {
                    let v = *get(&mut defaults);
                    if v != 0 {
                        line.push_str(&format!(" (default {v})"));
                    }
                }
                Slot::Str(get) => {
                    let v = get(&mut defaults).clone();
                    if !v.is_empty() {
                        line.push_str(&format!(" (default \"{v}\")"));
                    }
                }
                _ => {}
            }
        }
        eprintln!("{line}");
    }
}

/// Parses argv into the raw flag values. Accepts -name value,
/// --name value, -name=value and --name=value; a boolean flag takes
/// no value unless given as -name=true / -name=false. `Ok(true)` for
/// -h / --help (usage printed); `Err` after printing the error.
fn parse_argv(args: &[String], f: &mut RawFlags) -> Result<bool, ()> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with('-') || arg.len() == 1 {
            eprintln!("loop: unexpected positional arguments: [{arg}]");
            return Err(());
        }
        let name = arg.strip_prefix("--").unwrap_or(&arg[1..]);
        if name == "h" || name == "help" {
            usage();
            return Ok(true);
        }
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (name, None),
        };
        let Some(fl) = FLAGS.iter().find(|fl| fl.name == name) else {
            eprintln!("loop: flag provided but not defined: -{name}");
            usage();
            return Err(());
        };
        let value = match inline {
            Some(v) => v,
            None => match &fl.slot {
                Slot::Bool(_) => "true".to_string(),
                _ => {
                    i += 1;
                    match args.get(i) {
                        Some(v) => v.clone(),
                        None => {
                            eprintln!("loop: flag needs an argument: -{}", fl.name);
                            return Err(());
                        }
                    }
                }
            },
        };
        let ok = match &fl.slot {
            Slot::Int(get) => value.parse::<i64>().map(|v| *get(f) = v).is_ok(),
            Slot::Uint(get) => value.parse::<u64>().map(|v| *get(f) = v).is_ok(),
            Slot::Str(get) => {
                *get(f) = value.clone();
                true
            }
            Slot::Bool(get) => match value.as_str() {
                "true" => {
                    *get(f) = true;
                    true
                }
                "false" => {
                    *get(f) = false;
                    true
                }
                _ => false,
            },
        };
        if !ok {
            eprintln!("loop: invalid value \"{value}\" for flag -{}", fl.name);
            return Err(());
        }
        i += 1;
    }
    Ok(false)
}

/// Whether name is in the shipped hash registry the binding returns.
fn hash_registered(name: &str) -> bool {
    itb3::hash_names()
        .map(|v| v.iter().any(|n| n == name))
        .unwrap_or(false)
}

/// Resolves a registered profile to the shape family its record's
/// mode exposes by reading the record through the binding's lookup:
/// a mode beginning with "streaming" exposes the stream surfaces, one
/// beginning with "singlemsg" the message surface, "blob-only" none.
/// Prints the validation message and returns `None` on rejection.
fn profile_surface(name: &str) -> Option<Shape> {
    let Ok(p) = itb3::lookup(name) else {
        eprintln!("loop: --profile \"{name}\" is not a registered triple profile");
        return None;
    };
    if p.mode.starts_with("streaming") {
        Some(Shape::Stream)
    } else if p.mode.starts_with("singlemsg") {
        Some(Shape::Message)
    } else {
        eprintln!("loop: --profile \"{name}\" carries no cipher surface (blob-only mode)");
        None
    }
}

/// Applies a --profile's surface to the requested shape: a
/// message-surface profile forces message; a stream-surface profile
/// keeps stream or stream_one_shot as requested and turns message or
/// both into stream.
fn narrow_shape(requested: Shape, surface: Shape) -> Shape {
    if surface == Shape::Message {
        Shape::Message
    } else if requested == Shape::StreamOneShot {
        Shape::StreamOneShot
    } else {
        Shape::Stream
    }
}

/// Builds the resolved config from argv. `Ok(None)` for help; `Err`
/// after printing "loop: <message>" for the first failing rule.
fn parse_flags(args: &[String]) -> Result<Option<Config>, ()> {
    let mut f = RawFlags::default();
    if parse_argv(args, &mut f)? {
        return Ok(None);
    }
    let duration_ns = match parse_duration(&f.duration) {
        Some(d) if d > 0 => d,
        _ => {
            eprintln!("loop: --duration must be positive, got {}", f.duration);
            return Err(());
        }
    };
    if f.iterations < 0 {
        eprintln!("loop: --iterations must be >= 0, got {}", f.iterations);
        return Err(());
    }
    if f.goroutines < 1 || f.goroutines > MAX_WORKERS as i64 {
        eprintln!(
            "loop: --goroutines must be in 1..{MAX_WORKERS}, got {}",
            f.goroutines
        );
        return Err(());
    }
    // Concurrency mode. This binding runs shared-handle: OS threads
    // call into one Pipeline handle concurrently, which the shared
    // library permits after construction and the binding's Pipeline
    // type allows (it is Send + Sync by construction), so --goroutines
    // is the thread count verbatim, never clamped.
    let workers = f.goroutines as usize;
    let Some(mut shape) = Shape::parse(&f.shape) else {
        eprintln!(
            "loop: --shape must be stream | message | stream_one_shot | both, got \"{}\"",
            f.shape
        );
        return Err(());
    };
    if !hash_registered(&f.hash) {
        eprintln!(
            "loop: --hash \"{}\" is not a registered hash primitive",
            f.hash
        );
        return Err(());
    }
    // --mac is validated by Init: the C ABI enumerates no MAC names.
    let Some(payload) = parse_size(&f.payload_size) else {
        eprintln!("loop: --payload-size: invalid size \"{}\"", f.payload_size);
        return Err(());
    };
    if payload < 1 {
        eprintln!("loop: --payload-size must be at least 1 byte");
        return Err(());
    }
    let memlimit_auto = f.memlimit == "auto";
    let memlimit = if memlimit_auto {
        if workers <= 3 { 1 << 30 } else { 256 << 20 }
    } else {
        match parse_size(&f.memlimit) {
            Some(v) => v,
            None => {
                eprintln!("loop: --memlimit: invalid size \"{}\"", f.memlimit);
                return Err(());
            }
        }
    };
    if f.gogc < 0 {
        eprintln!("loop: --gogc must be >= 0, got {}", f.gogc);
        return Err(());
    }
    let parallax = match f.parallax.as_str() {
        "on" => true,
        "off" => false,
        v => {
            eprintln!("loop: --parallax must be on | off, got \"{v}\"");
            return Err(());
        }
    };
    let wrapper = match f.wrapper.as_str() {
        "on" => true,
        "off" => false,
        v => {
            eprintln!("loop: --wrapper must be on | off, got \"{v}\"");
            return Err(());
        }
    };
    if !f.profile.is_empty() {
        let Some(surface) = profile_surface(&f.profile) else {
            return Err(());
        };
        shape = narrow_shape(shape, surface);
    }
    if !matches!(f.key_bits, 0 | 512 | 1024 | 2048) {
        eprintln!(
            "loop: --key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got {}",
            f.key_bits
        );
        return Err(());
    }
    if !matches!(f.nonce_bits, 0 | 128 | 256 | 512) {
        eprintln!(
            "loop: --nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got {}",
            f.nonce_bits
        );
        return Err(());
    }
    if !matches!(f.blob_mode, 1 | 2) {
        eprintln!(
            "loop: --blob-mode must be 1 (per-region) | 2 (per-container), got {}",
            f.blob_mode
        );
        return Err(());
    }
    if !matches!(f.barrier_fill, 0 | 1 | 2 | 4 | 8 | 16 | 32) {
        eprintln!(
            "loop: --barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got {}",
            f.barrier_fill
        );
        return Err(());
    }
    // --drbg is validated by Init: the C ABI enumerates no DRBG names.
    let Some(chunk_size) = parse_size(&f.chunk_size) else {
        eprintln!("loop: --chunk-size: invalid size \"{}\"", f.chunk_size);
        return Err(());
    };
    if f.gomaxprocs < 0 {
        eprintln!(
            "loop: --gomaxprocs must be > 0 when specified, got {}",
            f.gomaxprocs
        );
        return Err(());
    }
    if f.rekey_every < 0 {
        eprintln!("loop: --rekey-every must be >= 0, got {}", f.rekey_every);
        return Err(());
    }
    if f.blob_cycle_every < 0 {
        eprintln!(
            "loop: --blob-cycle-every must be >= 0, got {}",
            f.blob_cycle_every
        );
        return Err(());
    }
    let Some(payload_mode) = PayloadMode::parse(&f.payload_mode) else {
        eprintln!(
            "loop: --payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"{}\"",
            f.payload_mode
        );
        return Err(());
    };
    Ok(Some(Config {
        duration_ns,
        iterations: f.iterations,
        workers_requested: workers,
        workers,
        shape,
        hash: f.hash,
        mac: f.mac,
        payload,
        memlimit,
        memlimit_auto,
        gogc: f.gogc as i32,
        parallax,
        wrapper,
        profile: f.profile,
        key_bits: f.key_bits,
        nonce_bits: f.nonce_bits,
        blob_mode: f.blob_mode,
        chunk_size,
        barrier_fill: f.barrier_fill,
        drbg: f.drbg,
        gomaxprocs: f.gomaxprocs as i32,
        rekey_every: f.rekey_every,
        blob_cycle_every: f.blob_cycle_every,
        payload_mode,
        seed: f.seed,
        json_output: f.json_output,
        memprofile: f.memprofile,
    }))
}

// ------------------------------------------------------------------
// Signals
// ------------------------------------------------------------------

static SIGNAL_SEEN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SIGNAL_SEEN.store(true, Ordering::SeqCst);
}

/// Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
/// while it waits for the workers; it turns the flag into the stop
/// request every worker checks before starting an iteration, so a
/// signal interrupts nothing mid-call — the in-flight encrypt /
/// decrypt / compare completes, the worker returns, and the partial
/// summary prints with the verdict the completed iterations earned.
fn install_signals() {
    // SAFETY: the handler only stores an atomic flag, which is
    // async-signal-safe; both signals default to termination, so
    // replacing their disposition cannot break the process.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

// ------------------------------------------------------------------
// Pipelines
// ------------------------------------------------------------------

/// Supplies the keystream-capable primitive for every layer the
/// profile record leaves unnamed and the run engages: a missing
/// parallax palette becomes three copies of the fill cipher (with the
/// library's default segment size when the record carries none), a
/// missing outer cipher becomes the fill cipher. These are opts
/// overrides that fold into the resolved record the blob carries — a
/// derived profile is never registered, so no name the receiver did
/// not agree to reaches the wire. `Ok(true)` when anything was
/// filled; `Err` after printing the validation message.
fn fill_keystream_layers(
    name: &str,
    opts: OptsBuilder,
    want_parallax: bool,
    want_wrapper: bool,
) -> Result<(OptsBuilder, bool), ()> {
    let Ok(p) = itb3::lookup(name) else {
        eprintln!("loop: --profile \"{name}\" is not a registered triple profile");
        return Err(());
    };
    let mut opts = opts;
    let mut filled = false;
    if want_parallax && p.parallax_palette.is_empty() {
        opts = opts.with_parallax_palette(&[KEYSTREAM_FILL_CIPHER; 3]);
        if p.parallax_segment_size == 0 {
            // A recipe that never carried a palette never carried a
            // segment size either, and the schedule rejects zero.
            opts = opts.with_parallax_segment_size(KEYSTREAM_FILL_SEGMENT);
        }
        filled = true;
    }
    if want_wrapper && p.outer_cipher.is_empty() {
        opts = opts.with_outer_cipher(KEYSTREAM_FILL_CIPHER);
        filled = true;
    }
    Ok((opts, filled))
}

/// Constructs one Pipeline against profile with every flag-carried
/// override in the opts string (zero values included — the shared
/// library treats zero as "profile default"), then obtains the Init
/// blob once through save: the binding's init entry does not hand the
/// blob back, and the bytes are the ones Init produced. Later blob
/// reopens use the retained blob; save is never called again.
fn build_pipeline(cfg: &Config, profile: &str) -> Result<(Pipeline, Vec<u8>), ()> {
    let mut opts = OptsBuilder::new()
        .with_inner_hash(&cfg.hash)
        .with_mac_name(&cfg.mac)
        .with_parallax(cfg.parallax)
        .with_wrapper(cfg.wrapper)
        .with_key_bits(cfg.key_bits)
        .with_nonce_bits(cfg.nonce_bits)
        .with_barrier_fill(cfg.barrier_fill)
        .with_drbg(&cfg.drbg)
        .with_chunk_size(cfg.chunk_size);
    if !cfg.profile.is_empty() {
        let (o, filled) = fill_keystream_layers(&cfg.profile, opts, cfg.parallax, cfg.wrapper)?;
        opts = o;
        if filled {
            eprintln!(
                "loop: {} leaves the requested keystream layers unnamed; {} supplied for them",
                cfg.profile, KEYSTREAM_FILL_CIPHER
            );
        }
    }
    let mut pipe = match Pipeline::init(profile, &opts) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("loop: Init({profile}): {}", worker::detail(&e));
            return Err(());
        }
    };
    let mut blob = match pipe.save() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("loop: Save({profile}): {}", worker::detail(&e));
            return Err(());
        }
    };
    if cfg.blob_mode == 2 {
        // The sizing mode is not an Opts knob: the Init blob is edited
        // and the pipeline reopened from it, so the retained blob (the
        // one blob-cycle reopens from) carries the edited mode.
        if edit_inner_blob_mode(&mut blob, 2).is_none() {
            eprintln!("loop: rewrite blob mode: inner blob mode field not found");
            return Err(());
        }
        drop(pipe);
        pipe = match Pipeline::load(&blob, None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("loop: reload Mode 2 blob: {}", worker::detail(&e));
                return Err(());
            }
        };
    }
    log_pipeline_initialised(profile, &blob);
    Ok((pipe, blob))
}

/// Sets the inner blob's "mode" field of a wrap-layer session blob to
/// target_mode (1 = per-region, 2 = per-container) in place. The wrap
/// layer's profile record carries its own "mode" (a string), so the
/// search starts at the inner blob ("ib"); both shipped modes are one
/// digit wide, so the blob length does not change. `None` when the
/// inner blob or its mode field is not found.
fn edit_inner_blob_mode(blob: &mut [u8], target_mode: u8) -> Option<()> {
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
    let ib_key = b"\"ib\":{";
    let mode_key = b"\"mode\":";
    let off = find(blob, ib_key)? + ib_key.len();
    let at = off + find(&blob[off..], mode_key)? + mode_key.len();
    if at + 1 >= blob.len() || !(b'1'..=b'2').contains(&blob[at]) || blob[at + 1].is_ascii_digit() {
        return None;
    }
    blob[at] = b'0' + target_mode;
    Some(())
}

/// Prints the construction line with the recipe read back from the
/// blob the Pipeline handed out, not echoed from the flags: every
/// construction override is proven to have reached the library by the
/// value the receiver would see. Record values that are empty (a No
/// MAC profile's MAC, a mixed profile's single hash) print as "-".
fn log_pipeline_initialised(profile: &str, blob: &[u8]) {
    let rec = match itb3::inspect(blob) {
        Ok(r) => r,
        Err(e) => {
            log_line(&format!(
                "pipeline initialised: profile={profile} blob={} bytes (inspect: {})",
                blob.len(),
                worker::detail(&e)
            ));
            return;
        }
    };
    let dash = |s: &str| {
        if s.is_empty() {
            "-".to_string()
        } else {
            s.to_string()
        }
    };
    let mut line = format!(
        "pipeline initialised: profile={profile} blob={} bytes hash={} key-bits={} nonce-bits={} barrier-fill={} chunk-size={} mac={} parallax={} wrapper={}",
        blob.len(),
        dash(&rec.inner_hash),
        rec.key_bits,
        rec.nonce_bits.unwrap_or(0),
        rec.barrier_fill.unwrap_or(0),
        rec.chunk_size,
        dash(&rec.mac_name),
        on_off(rec.parallax),
        on_off(rec.wrapper)
    );
    if rec.container_mode == Some(2) {
        line.push_str(" container-mode=2");
    }
    if !rec.drbg.is_empty() {
        line.push_str(&format!(" drbg={}", rec.drbg));
    }
    log_line(&line);
}

// ------------------------------------------------------------------
// Run
// ------------------------------------------------------------------

fn run(args: &[String]) -> i32 {
    let mut cfg = match parse_flags(args) {
        Ok(Some(c)) => c,
        Ok(None) => return 0,
        Err(()) => return 2,
    };

    // Runtime shaping. A long run under allocation churn grows the
    // Go heap inside the shared library without bound unless a soft
    // limit paces the collector, so a limit is always in force: an
    // explicit --memlimit is set as given, and auto caps the heap
    // only when the runtime reports no limit at all (a limit already
    // installed from the environment is left standing). The GC
    // percentage and GOMAXPROCS are set only when their flag is
    // non-zero — a zero flag skips the setter rather than calling it
    // with zero, because zero is a real value to the GC-percent
    // setter, and a call would clobber whatever the environment
    // installed. All of it lands before any Pipeline exists so the
    // baselines are taken under the shaped runtime.
    if cfg.memlimit_auto {
        if itb3::set_memory_limit(-1).unwrap_or(0) == i64::MAX {
            let _ = itb3::set_memory_limit(cfg.memlimit);
        }
    } else {
        let _ = itb3::set_memory_limit(cfg.memlimit);
    }
    cfg.memlimit = itb3::set_memory_limit(-1).unwrap_or(cfg.memlimit);
    if cfg.gogc > 0 {
        let _ = itb3::set_gc_percent(cfg.gogc);
    }
    if cfg.gomaxprocs > 0 {
        let _ = itb3::set_gomaxprocs(cfg.gomaxprocs);
    }

    log_line(&format!(
        "start: duration={} iterations={} goroutines={} workers={} concurrency={CONCURRENCY} shape={} hash={} mac={} payload={} memlimit={} parallax={} wrapper={}",
        human_duration(cfg.duration_ns),
        cfg.iterations,
        cfg.workers_requested,
        cfg.workers,
        cfg.shape.name(),
        cfg.hash,
        cfg.mac,
        human_bytes(cfg.payload),
        human_bytes(cfg.memlimit),
        on_off(cfg.parallax),
        on_off(cfg.wrapper)
    ));
    let mut overrides = format!(
        "overrides: profile=\"{}\" key-bits={} nonce-bits={} chunk-size={} barrier-fill={} gomaxprocs={} rekey-every={} blob-cycle-every={} payload-mode={} seed={} json-output={}",
        cfg.profile,
        cfg.key_bits,
        cfg.nonce_bits,
        human_bytes(cfg.chunk_size),
        cfg.barrier_fill,
        cfg.gomaxprocs,
        cfg.rekey_every,
        cfg.blob_cycle_every,
        cfg.payload_mode.name(),
        cfg.seed,
        cfg.json_output
    );
    if cfg.blob_mode != 1 {
        overrides.push_str(&format!(" blob-mode={}", cfg.blob_mode));
    }
    if !cfg.drbg.is_empty() {
        overrides.push_str(&format!(" drbg={}", cfg.drbg));
    }
    log_line(&overrides);
    log_line(&format!(
        "policy: microbatch-tiers={} hashpool-starters={}",
        policy_label(std::env::var("ITB_MICROBATCH_TIERS").ok()),
        policy_label(std::env::var("ITB_HASHPOOL_STARTERS").ok())
    ));

    // Pipeline construction — one shared handle per exercised shape.
    // stream and stream_one_shot share the streaming handle.
    let stream_profile = if cfg.profile.is_empty() {
        DEFAULT_STREAM_PROFILE
    } else {
        &cfg.profile
    }
    .to_string();
    let msg_profile = if cfg.profile.is_empty() {
        DEFAULT_MESSAGE_PROFILE
    } else {
        &cfg.profile
    }
    .to_string();
    let mut pipes = Pipes {
        stream: None,
        msg: None,
        stream_blob: Vec::new(),
        msg_blob: Vec::new(),
    };
    if matches!(
        cfg.shape,
        Shape::Stream | Shape::StreamOneShot | Shape::Both
    ) {
        match build_pipeline(&cfg, &stream_profile) {
            Ok((p, b)) => {
                pipes.stream = Some(p);
                pipes.stream_blob = b;
            }
            Err(()) => return 1,
        }
    }
    if matches!(cfg.shape, Shape::Message | Shape::Both) {
        match build_pipeline(&cfg, &msg_profile) {
            Ok((p, b)) => {
                pipes.msg = Some(p);
                pipes.msg_blob = b;
            }
            Err(()) => return 1,
        }
    }

    // Allocation posture. Per-worker plaintexts are allocated once and
    // held for the whole run (rotating mode refills them in place per
    // iteration); the pump accumulators live inside each worker and
    // are reused across iterations; the message and one-shot outputs
    // are allocated by the binding per call and dropped per iteration.
    // Under the default fixed CSPRNG mode every worker's buffer is
    // distinct, so cross-worker data crossover is detectable; pattern
    // modes trade that property for content edge-case coverage.
    let mut states = Vec::with_capacity(cfg.workers);
    for id in 0..cfg.workers {
        let mut w = WorkerState {
            id,
            plaintext: vec![0u8; cfg.payload as usize],
            payload_mode: cfg.payload_mode,
            seeded: cfg.seed != 0,
            rng: seed_worker(cfg.seed, id),
            wire: Vec::new(),
            plain: Vec::new(),
        };
        if !fill_payload(cfg.payload_mode, w.seeded, &mut w.rng, &mut w.plaintext) {
            eprintln!("loop: payload fill: csprng");
            return 1;
        }
        states.push(w);
    }

    install_signals();
    let workers = cfg.workers;
    let iterations = cfg.iterations;
    let duration = Duration::from_nanos(cfg.duration_ns as u64);
    let memprofile = cfg.memprofile.clone();
    let mut r = RunState {
        cfg,
        stream_profile,
        msg_profile,
        pipes: RwLock::new(pipes),
        rekeys: AtomicI64::new(0),
        blob_cycles: AtomicI64::new(0),
        workers: (0..workers).map(|_| Counters::default()).collect(),
        warmup_done: Barrier::new(workers + 1),
        release: Barrier::new(workers + 1),
        stop: AtomicBool::new(false),
        done: Mutex::new(Done {
            active: workers,
            finish: None,
        }),
        done_cv: Condvar::new(),
        rss_warmup: 0,
        rss_peak: 0,
        rss_final: 0,
        pool_warmup: Vec::new(),
        pool_steady: Vec::new(),
    };

    // Warmup barrier. Every worker runs one iteration and waits; the
    // clock starts only once all of them have paid their first-call
    // costs (pool warm-up, lazy kernel dispatch, page faults on the
    // payload buffers), and the RSS and pool baselines taken here
    // describe a process that has already run the whole cipher path
    // once per worker.
    let warmup_start = Instant::now();
    let (elapsed_ns, rss_final, rss_peak, pool_steady, rss_warmup, pool_warmup) =
        std::thread::scope(|scope| {
            let rs = &r;
            for w in states {
                scope.spawn(move || worker::run(rs, w));
            }
            rs.warmup_done.wait();
            let (rss_warmup, _) = summary::read_rss();
            let pool_warmup = summary::pool_snapshot();
            let warmup_ns = warmup_start.elapsed().as_nanos() as i64;
            log_line(&format!(
                "warmup: {workers} workers x 1 iter completed in {} (baseline rss={})",
                human_duration(round_to(warmup_ns, 100_000_000)),
                human_bytes(rss_warmup as i64)
            ));

            // Open the gate; the duration is a deadline the waiter
            // below enforces in duration mode.
            let start = Instant::now();
            rs.release.wait();

            // Wait for every worker, polling every 100 ms so the
            // deadline and a signal are both noticed promptly.
            let mut finish = start;
            let mut d = rs.done.lock().unwrap();
            while d.active > 0 {
                if SIGNAL_SEEN.load(Ordering::SeqCst)
                    || (iterations == 0 && start.elapsed() >= duration)
                {
                    rs.stop.store(true, Ordering::SeqCst);
                }
                d = rs
                    .done_cv
                    .wait_timeout(d, Duration::from_millis(100))
                    .unwrap()
                    .0;
            }
            if let Some(f) = d.finish {
                finish = f;
            }
            drop(d);
            let elapsed_ns = finish.duration_since(start).as_nanos() as i64;
            let (rss_final, rss_peak) = summary::read_rss();
            let pool_steady = summary::pool_snapshot();
            (
                elapsed_ns,
                rss_final,
                rss_peak,
                pool_steady,
                rss_warmup,
                pool_warmup,
            )
        });
    r.rss_warmup = rss_warmup;
    r.rss_peak = rss_peak;
    r.rss_final = rss_final;
    r.pool_warmup = pool_warmup;
    r.pool_steady = pool_steady;

    if !memprofile.is_empty() {
        match itb3::write_heap_profile(&memprofile) {
            Ok(()) => log_line(&format!("memprofile: heap profile written to {memprofile}")),
            Err(e) => eprintln!("loop: memprofile: {}", worker::detail(&e)),
        }
    }

    summary::final_summary(&r, elapsed_ns)
    // Rust-specific. Every handle and buffer is released by Drop when
    // `r` goes out of scope here; nothing is freed by hand.
}

fn main() -> ExitCode {
    // Rust-specific. The runtime ignores SIGPIPE before main runs, so
    // a write to a closed stdout panics with exit 101 instead of
    // ending the process. Restoring the signal's default disposition
    // ends it on the spot, which is what every other implementation
    // does and what a fleet driver expects.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args) as u8)
}
