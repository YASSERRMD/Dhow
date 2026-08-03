//! QR encoding of wire frames.
//!
//! Each wire frame becomes exactly one QR code. The mapping is 1:1 and
//! deterministic: the same frame always produces the same module matrix, which
//! is what lets a sender loop a frame stream on screen and a receiver treat
//! every capture of the same frame as interchangeable.
//!
//! # Choosing a frame size
//!
//! A frame must fit in one QR code, so the codec's symbol size is bounded by
//! QR capacity rather than the other way round. [`capacity`] reports how many
//! bytes a given version and error-correction level holds, and
//! [`max_symbol_size`] converts that into the symbol size a caller may ask the
//! chunker for.
//!
//! These numbers come from `qrcodegen` itself rather than from a table copied
//! out of the specification, so they cannot drift from what the encoder
//! actually accepts. `scripts/gen_qr_capacity.sh` renders them into
//! `proto/qr-capacity.md` for reference.
//!
//! # Error correction
//!
//! Higher error correction survives a worse camera at the cost of fewer
//! payload bytes per frame. The choice belongs to the operator, who knows the
//! lighting and the distance, so it is a parameter rather than a constant.
//! RaptorQ repair symbols already handle a frame that is lost outright; QR
//! error correction handles a frame that is *partially* readable, which is the
//! common case with a real camera.

use qrcodegen::{QrCode, QrCodeEcc, Version};

/// Error type for QR encoding operations.
#[derive(Debug, thiserror::Error)]
pub enum QrError {
    /// The input data is too large for the requested version.
    #[error(
        "data too large for QR encoding: {length} bytes exceeds the capacity of version {version} at {ecc:?}"
    )]
    DataTooLong {
        length: usize,
        version: u8,
        ecc: Ecc,
    },

    /// The requested QR version is outside 1..=40.
    #[error("invalid QR version {version}, must be 1..=40")]
    InvalidVersion { version: u8 },
}

/// Error-correction level, mirroring the QR specification's four levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ecc {
    /// Recovers roughly 7% of codewords.
    Low,
    /// Recovers roughly 15% of codewords. The default: it survives ordinary
    /// camera noise without spending an excessive share of each frame.
    #[default]
    Medium,
    /// Recovers roughly 25% of codewords.
    Quartile,
    /// Recovers roughly 30% of codewords.
    High,
}

impl Ecc {
    fn to_qrcodegen(self) -> QrCodeEcc {
        match self {
            Ecc::Low => QrCodeEcc::Low,
            Ecc::Medium => QrCodeEcc::Medium,
            Ecc::Quartile => QrCodeEcc::Quartile,
            Ecc::High => QrCodeEcc::High,
        }
    }

    /// Parses a level from its single-letter name.
    pub fn from_letter(c: char) -> Option<Self> {
        match c.to_ascii_uppercase() {
            'L' => Some(Ecc::Low),
            'M' => Some(Ecc::Medium),
            'Q' => Some(Ecc::Quartile),
            'H' => Some(Ecc::High),
            _ => None,
        }
    }

    /// Returns the single-letter name of this level.
    pub fn letter(self) -> char {
        match self {
            Ecc::Low => 'L',
            Ecc::Medium => 'M',
            Ecc::Quartile => 'Q',
            Ecc::High => 'H',
        }
    }
}

/// Lowest QR version.
pub const MIN_VERSION: u8 = 1;

/// Highest QR version.
pub const MAX_VERSION: u8 = 40;

/// Returns how many bytes fit in one QR code at `version` and `ecc`.
///
/// Measured against the encoder rather than read from a copied table: the
/// answer is whatever `qrcodegen` will actually accept in byte mode.
pub fn capacity(version: u8, ecc: Ecc) -> Result<usize, QrError> {
    if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
        return Err(QrError::InvalidVersion { version });
    }

    // Measured by asking the encoder, not derived from a copied table. The
    // codeword arithmetic in the specification is easy to transcribe subtly
    // wrong, and a capacity that is one byte optimistic would fail only for
    // the frames that happen to fill a version exactly. Binary searching the
    // real encoder cannot disagree with it.
    //
    // The version and level pair is fixed for a whole transfer, so this runs
    // once per configuration rather than once per frame.
    let mut low = 0usize;
    let mut high = 4096usize;

    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if fits(mid, version, ecc) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }

    Ok(low)
}

/// Reports whether `len` bytes encode at `version` and `ecc`.
fn fits(len: usize, version: u8, ecc: Ecc) -> bool {
    let v = Version::new(version);
    let data = vec![0u8; len];
    let segments = [qrcodegen::QrSegment::make_bytes(&data)];
    QrCode::encode_segments_advanced(&segments, ecc.to_qrcodegen(), v, v, None, false).is_ok()
}

/// Returns the largest codec symbol size that still fits one QR code.
///
/// A frame is a 46-byte header, a 4-byte RaptorQ payload identifier, and the
/// symbol itself, so the symbol gets whatever remains. Returns `None` when the
/// version is too small to hold even a one-byte symbol.
pub fn max_symbol_size(version: u8, ecc: Ecc) -> Result<Option<u32>, QrError> {
    const FRAME_OVERHEAD: usize = crate::frame::FRAME_HEADER_SIZE + 4;

    let cap = capacity(version, ecc)?;
    if cap <= FRAME_OVERHEAD {
        return Ok(None);
    }
    Ok(Some((cap - FRAME_OVERHEAD) as u32))
}

/// Returns the smallest version that holds `len` bytes at `ecc`.
///
/// Choosing the smallest workable version keeps the module grid coarse, which
/// matters because a coarser grid is what a camera at a given distance can
/// still resolve.
pub fn smallest_version_for(len: usize, ecc: Ecc) -> Option<u8> {
    (MIN_VERSION..=MAX_VERSION).find(|&v| capacity(v, ecc).is_ok_and(|c| c >= len))
}

/// A QR code holding one wire frame.
pub struct QrCodeEncoder {
    inner: QrCode,
    ecc: Ecc,
}

impl QrCodeEncoder {
    /// Encodes binary data at medium error correction, choosing the version.
    pub fn encode(data: &[u8]) -> Result<Self, QrError> {
        Self::encode_with(data, Ecc::Medium)
    }

    /// Encodes binary data at `ecc`, choosing the smallest workable version.
    pub fn encode_with(data: &[u8], ecc: Ecc) -> Result<Self, QrError> {
        let inner =
            QrCode::encode_binary(data, ecc.to_qrcodegen()).map_err(|_| QrError::DataTooLong {
                length: data.len(),
                version: MAX_VERSION,
                ecc,
            })?;
        Ok(Self { inner, ecc })
    }

    /// Encodes binary data at a fixed version and error-correction level.
    ///
    /// Pinning the version keeps every frame in a stream the same physical
    /// size on screen. A stream whose frames changed size mid-transfer would
    /// force the receiver to re-acquire focus and framing on each change.
    pub fn encode_at(data: &[u8], version: u8, ecc: Ecc) -> Result<Self, QrError> {
        if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
            return Err(QrError::InvalidVersion { version });
        }
        if data.len() > capacity(version, ecc)? {
            return Err(QrError::DataTooLong {
                length: data.len(),
                version,
                ecc,
            });
        }

        let v = Version::new(version);
        let segments = [qrcodegen::QrSegment::make_bytes(data)];
        let inner = QrCode::encode_segments_advanced(
            &segments,
            ecc.to_qrcodegen(),
            v,
            v,
            None,
            // Boosting the error-correction level would silently change the
            // frame's decode characteristics away from what the operator
            // chose, so it is disabled.
            false,
        )
        .map_err(|_| QrError::DataTooLong {
            length: data.len(),
            version,
            ecc,
        })?;

        Ok(Self { inner, ecc })
    }

    /// Returns the QR version (1-40).
    pub fn version(&self) -> u8 {
        self.inner.version().value()
    }

    /// Returns the error-correction level used.
    pub fn ecc(&self) -> Ecc {
        self.ecc
    }

    /// Returns the number of modules per side.
    pub fn size(&self) -> usize {
        self.inner.size() as usize
    }

    /// Returns whether the module at (x, y) is dark.
    ///
    /// Coordinates outside the grid read as light, matching `qrcodegen`, so a
    /// renderer that walks a quiet zone needs no bounds check.
    pub fn get_module(&self, x: usize, y: usize) -> bool {
        self.inner.get_module(x as i32, y as i32)
    }

    /// Returns the module grid as one byte per module, row-major, 1 for dark.
    ///
    /// This is the form the renderer consumes and the form that crosses the
    /// FFI boundary: one allocation, no per-module calls.
    pub fn to_modules(&self) -> Vec<u8> {
        let size = self.size();
        let mut out = Vec::with_capacity(size * size);
        for y in 0..size {
            for x in 0..size {
                out.push(u8::from(self.get_module(x, y)));
            }
        }
        out
    }

    /// Renders the QR code as a terminal string using block characters.
    ///
    /// Each module is two characters wide, because terminal cells are roughly
    /// twice as tall as they are wide and a square module is what a scanner
    /// expects.
    pub fn to_terminal(&self) -> String {
        let size = self.size();
        let mut output = String::with_capacity(size * (size * 2 + 1));
        for y in 0..size {
            for x in 0..size {
                output.push_str(if self.get_module(x, y) {
                    "██"
                } else {
                    "  "
                });
            }
            output.push('\n');
        }
        output
    }

    /// Returns the underlying qrcodegen QrCode.
    pub fn inner(&self) -> &QrCode {
        &self.inner
    }
}
