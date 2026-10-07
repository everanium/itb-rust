//! Size and duration parsing and the human renderings of sizes, rates
//! and durations. Every rendering here is part of the output contract
//! shared with the Go harness and the other bindings' loop utilities,
//! so the formats are fixed to the character, not to taste.

/// Parses a human byte-size string ("16MB", "1MiB", "512K",
/// "1073741824") into a byte count. Every suffix is a binary multiple:
/// K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
/// bytes; matching is case-insensitive and surrounding whitespace is
/// trimmed. `None` on a malformed or negative value.
pub fn parse_size(s: &str) -> Option<i64> {
    let upper = s.trim().to_ascii_uppercase();
    if upper.is_empty() {
        return None;
    }
    const TABLE: [(&str, i64); 10] = [
        ("KIB", 1 << 10),
        ("KB", 1 << 10),
        ("K", 1 << 10),
        ("MIB", 1 << 20),
        ("MB", 1 << 20),
        ("M", 1 << 20),
        ("GIB", 1 << 30),
        ("GB", 1 << 30),
        ("G", 1 << 30),
        ("B", 1),
    ];
    let mut mult = 1i64;
    let mut digits = upper.as_str();
    for (suffix, m) in TABLE {
        if let Some(rest) = upper.strip_suffix(suffix) {
            mult = m;
            digits = rest;
            break;
        }
    }
    let digits = digits.trim_end();
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    n.checked_mul(mult)
}

/// Parses the Go duration grammar — a sequence of decimal numbers each
/// followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
/// "1h30m", "1.5s" — into nanoseconds. `None` on a malformed string.
pub fn parse_duration(s: &str) -> Option<i64> {
    const UNITS: [(&str, f64); 6] = [
        ("ns", 1.0),
        ("us", 1e3),
        ("ms", 1e6),
        ("s", 1e9),
        ("m", 60e9),
        ("h", 3600e9),
    ];
    if s.is_empty() {
        return None;
    }
    let mut rest = s;
    let mut total = 0.0f64;
    while !rest.is_empty() {
        let num_len = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if num_len == 0 {
            return None;
        }
        let v: f64 = rest[..num_len].parse().ok()?;
        rest = &rest[num_len..];
        let mut matched = None;
        for (unit, ns) in UNITS {
            if let Some(after) = rest.strip_prefix(unit) {
                if after.starts_with(|c: char| c.is_ascii_alphabetic()) {
                    continue;
                }
                matched = Some((after, ns));
                break;
            }
        }
        let (after, ns) = matched?;
        rest = after;
        total += v * ns;
    }
    if total > 9.2e18 {
        return None;
    }
    Some(total as i64)
}

/// Renders a byte count with a binary-unit suffix: "1.0GiB",
/// "16.0MiB", "4.0KiB", "512B".
pub fn human_bytes(n: i64) -> String {
    if n >= 1 << 30 {
        format!("{:.1}GiB", n as f64 / (1u64 << 30) as f64)
    } else if n >= 1 << 20 {
        format!("{:.1}MiB", n as f64 / (1u64 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1}KiB", n as f64 / (1u64 << 10) as f64)
    } else {
        format!("{n}B")
    }
}

/// Renders a possibly-negative byte delta with an explicit sign.
pub fn human_bytes_signed(n: i64) -> String {
    if n < 0 {
        format!("-{}", human_bytes(-n))
    } else {
        format!("+{}", human_bytes(n))
    }
}

/// Binary MiB per second over a nanosecond window; 0 when the window
/// is unmeasured.
pub fn mb_per_sec(bytes: i64, ns: i64) -> f64 {
    if ns <= 0 {
        return 0.0;
    }
    bytes as f64 / (1u64 << 20) as f64 / (ns as f64 / 1e9)
}

/// Renders a throughput as "123.4MB/s" (binary MiB per second) or
/// "n/a" for an unmeasured window.
pub fn human_rate(bytes: i64, ns: i64) -> String {
    if ns <= 0 {
        return "n/a".to_string();
    }
    format!("{:.1}MB/s", mb_per_sec(bytes, ns))
}

/// The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
/// with trailing zeros removed; empty for zero.
fn fraction(frac_ns: i64) -> String {
    if frac_ns == 0 {
        return String::new();
    }
    let digits = format!("{frac_ns:09}");
    format!(".{}", digits.trim_end_matches('0'))
}

/// Renders a duration the way Go's `time.Duration` prints: zero as
/// "0s"; below one second as milliseconds ("900ms", "1.5ms");
/// otherwise "[Hh][Mm]Ss" where the hour part appears when non-zero,
/// the minute part when the hour part appears or the minutes are
/// non-zero, and the seconds carry their fraction with trailing zeros
/// removed ("5s", "5.003s", "1m0s", "1m5.25s", "1h0m0s"). The caller
/// rounds first.
pub fn human_duration(ns: i64) -> String {
    let ns = ns.abs();
    if ns == 0 {
        return "0s".to_string();
    }
    if ns < 1_000_000_000 {
        let ms = ns / 1_000_000;
        let frac = (ns % 1_000_000) * 1000; // scale to 9 digits
        return format!("{ms}{}ms", fraction(frac));
    }
    let hours = ns / 3_600_000_000_000;
    let rem = ns % 3_600_000_000_000;
    let minutes = rem / 60_000_000_000;
    let rem = rem % 60_000_000_000;
    let seconds = rem / 1_000_000_000;
    let frac = rem % 1_000_000_000;
    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if hours > 0 || minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    out.push_str(&format!("{seconds}{}s", fraction(frac)));
    out
}

/// Rounds a nanosecond count to the nearest multiple of `unit_ns`.
pub fn round_to(ns: i64, unit_ns: i64) -> i64 {
    (ns + unit_ns / 2) / unit_ns * unit_ns
}
