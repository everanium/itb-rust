//! eitb — command-line demonstrator for the ITB Rust binding.
//!
//! Subcommands:
//!
//!   eitb version                                   library + binding versions
//!   eitb profiles                                  registered profile catalogue
//!   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//!   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//!
//! `encrypt` prints the session blob to stderr as hex; feed that hex
//! back to `decrypt` on the receiving side. `profiles` lists the
//! registered profile catalogue one name per line; the profiles that
//! carry a cipher surface are the ones `encrypt` / `decrypt` accept.

use std::process::ExitCode;

use itb3::{OptsBuilder, Pipeline};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("version") if args.len() == 1 => cmd_version(),
        Some("profiles") if args.len() == 1 => cmd_profiles(),
        Some("encrypt") if args.len() == 4 => cmd_encrypt(&args[1], &args[2], &args[3]),
        Some("decrypt") if args.len() == 5 => cmd_decrypt(&args[1], &args[2], &args[3], &args[4]),
        _ => {
            eprintln!(
                "usage: eitb version\n       eitb profiles\n       \
                 eitb encrypt <profile> <in-file> <out-file>\n       \
                 eitb decrypt <profile> <blob-hex> <in-file> <out-file>"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eitb: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_version() -> Result<(), Box<dyn std::error::Error>> {
    println!("libitb3 {}", itb3::version()?);
    println!("itb-rust {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

/// Prints the registered profile catalogue one name per line in the
/// sorted order `itb3::profiles` returns.
fn cmd_profiles() -> Result<(), Box<dyn std::error::Error>> {
    for name in itb3::profiles()? {
        println!("{name}");
    }
    Ok(())
}

/// Create the parent directory of `out` recursively (analogue of
/// `mkdir -p $(dirname out)`). Silent if the directory already
/// exists; propagates the error otherwise.
fn ensure_parent_dir(out: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(out).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Profiles whose canonical name begins with `streaming-` route
/// through the one-shot streaming buffered pair instead of the
/// Single Message pair. On decrypt the profile shape travels inside
/// the blob; the argument only selects the cipher pair.
fn is_streaming_profile(profile: &str) -> bool {
    profile.starts_with("streaming-")
}

fn cmd_encrypt(
    profile: &str,
    infile: &str,
    outfile: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plain = std::fs::read(infile)?;
    let pipe = Pipeline::init(profile, &OptsBuilder::new())?;
    let wire = if is_streaming_profile(profile) {
        pipe.encrypt_stream_one_shot(&plain)?
    } else {
        pipe.encrypt_message(&plain)?
    };
    ensure_parent_dir(outfile)?;
    std::fs::write(outfile, &wire)?;
    eprintln!("{}", hex_encode(&pipe.save()?));
    println!(
        "encrypted {} -> {} ({} -> {} bytes)",
        infile,
        outfile,
        plain.len(),
        wire.len()
    );
    Ok(())
}

fn cmd_decrypt(
    profile: &str,
    blob_hex: &str,
    infile: &str,
    outfile: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let blob = hex_decode(blob_hex)?;
    let wire = std::fs::read(infile)?;
    let pipe = Pipeline::load(&blob, None)?;
    let plain = if is_streaming_profile(profile) {
        pipe.decrypt_stream_one_shot(&wire)?
    } else {
        pipe.decrypt_message(&wire)?
    };
    ensure_parent_dir(outfile)?;
    std::fs::write(outfile, &plain)?;
    println!(
        "decrypted {} -> {} ({} -> {} bytes)",
        infile,
        outfile,
        wire.len(),
        plain.len()
    );
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("blob hex has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("blob hex: {e}")))
        .collect()
}
