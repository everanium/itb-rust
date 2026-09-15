//! Status codes mirrored from the libitb3 C ABI
//! (`cmd/cshared/internal/capi/errors.go`). Numeric values are stable
//! across releases.

use std::fmt;

/// Integer status code returned by every libitb3 entry point.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItbStatus {
    Ok = 0,
    BadHash = 1,
    BadKeyBits = 2,
    BadHandle = 3,
    BadInput = 4,
    BufferTooSmall = 5,
    EncryptFailed = 6,
    DecryptFailed = 7,
    SeedWidthMix = 8,
    BadMac = 9,
    MacFailure = 10,
    BlobMalformedRecipe = 11,
    RecipePrimitiveUnknown = 12,
    UnknownProfile = 13,
    Reserved14 = 14,
    Reserved15 = 15,
    Reserved16 = 16,
    Reserved17 = 17,
    BlobModeMismatch = 19,
    BlobMalformed = 20,
    BlobVersionTooNew = 21,
    BlobTooManyOpts = 22,
    StreamTruncated = 23,
    StreamAfterFinal = 24,
    TripleClosed = 25,
    ProfileExists = 26,
    Internal = 99,
}

impl TryFrom<i32> for ItbStatus {
    type Error = i32;

    fn try_from(code: i32) -> Result<Self, i32> {
        Ok(match code {
            0 => Self::Ok,
            1 => Self::BadHash,
            2 => Self::BadKeyBits,
            3 => Self::BadHandle,
            4 => Self::BadInput,
            5 => Self::BufferTooSmall,
            6 => Self::EncryptFailed,
            7 => Self::DecryptFailed,
            8 => Self::SeedWidthMix,
            9 => Self::BadMac,
            10 => Self::MacFailure,
            11 => Self::BlobMalformedRecipe,
            12 => Self::RecipePrimitiveUnknown,
            13 => Self::UnknownProfile,
            14 => Self::Reserved14,
            15 => Self::Reserved15,
            16 => Self::Reserved16,
            17 => Self::Reserved17,
            19 => Self::BlobModeMismatch,
            20 => Self::BlobMalformed,
            21 => Self::BlobVersionTooNew,
            22 => Self::BlobTooManyOpts,
            23 => Self::StreamTruncated,
            24 => Self::StreamAfterFinal,
            25 => Self::TripleClosed,
            26 => Self::ProfileExists,
            99 => Self::Internal,
            other => return Err(other),
        })
    }
}

impl fmt::Display for ItbStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Ok => "ok",
            Self::BadHash => "unknown hash name",
            Self::BadKeyBits => "invalid key bits",
            Self::BadHandle => "invalid handle",
            Self::BadInput => "invalid input",
            Self::BufferTooSmall => "output buffer too small",
            Self::EncryptFailed => "encrypt failed",
            Self::DecryptFailed => "decrypt failed",
            Self::SeedWidthMix => "seed width mismatch",
            Self::BadMac => "unknown MAC name or invalid MAC handle",
            Self::MacFailure => "MAC verification failed",
            Self::BlobMalformedRecipe => "blob recipe malformed",
            Self::RecipePrimitiveUnknown => "blob recipe names an unknown primitive",
            Self::UnknownProfile => "unknown profile name",
            Self::Reserved14
            | Self::Reserved15
            | Self::Reserved16
            | Self::Reserved17 => "reserved status",
            Self::BlobModeMismatch => "blob mode mismatch",
            Self::BlobMalformed => "malformed state blob",
            Self::BlobVersionTooNew => "blob version too new",
            Self::BlobTooManyOpts => "too many blob export opts",
            Self::StreamTruncated => "stream truncated before terminator",
            Self::StreamAfterFinal => "stream chunk after terminator",
            Self::TripleClosed => "Triple Pipeline is closed",
            Self::ProfileExists => "profile name already registered",
            Self::Internal => "internal error",
        };
        f.write_str(label)
    }
}

impl std::error::Error for ItbStatus {}
