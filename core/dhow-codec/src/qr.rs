//! QR code encoding and terminal rendering.
//!
//! This module wraps the `qrcodegen` crate to encode frame bytes as QR codes,
//! and provides terminal rendering for local inspection.
//!
//! # Encoding
//!
//! Binary data is encoded using `QrCode::encode_binary` with medium error
//! correction, producing a square matrix of modules.
//!
//! # Terminal Rendering
//!
//! The `to_terminal` function renders a QR code as a string of `██`/`  `
//! blocks, suitable for display in any terminal.
//!
//! # Example
//!
//! ```
//! use dhow_codec::qr::QrCodeEncoder;
//!
//! let data = b"hello world";
//! let qr = QrCodeEncoder::encode(data).unwrap();
//! let terminal_str = qr.to_terminal();
//! assert!(!terminal_str.is_empty());
//! ```

use qrcodegen::{QrCode, QrCodeEcc};

/// Error type for QR encoding operations.
#[derive(Debug, thiserror::Error)]
pub enum QrError {
    /// The input data is too large for any QR code version.
    #[error("data too large for QR encoding")]
    DataTooLong,
}

/// Wrapper around qrcodegen's QrCode for Dhow.
pub struct QrCodeEncoder {
    inner: QrCode,
}

impl QrCodeEncoder {
    /// Encodes binary data as a QR code with medium error correction.
    pub fn encode(data: &[u8]) -> Result<Self, QrError> {
        let inner =
            QrCode::encode_binary(data, QrCodeEcc::Medium).map_err(|_| QrError::DataTooLong)?;
        Ok(Self { inner })
    }

    /// Returns the QR code version (1-40).
    pub fn version(&self) -> u8 {
        self.inner.version().value()
    }

    /// Returns the number of modules per side.
    pub fn size(&self) -> usize {
        self.inner.size() as usize
    }

    /// Returns whether the module at (x, y) is dark (true) or light (false).
    pub fn get_module(&self, x: usize, y: usize) -> bool {
        self.inner.get_module(x as i32, y as i32)
    }

    /// Renders the QR code as a terminal string using block characters.
    /// Each module is rendered as `██` (dark) or `  ` (light).
    pub fn to_terminal(&self) -> String {
        let size = self.size();
        let mut output = String::new();
        for y in 0..size {
            for x in 0..size {
                if self.get_module(x, y) {
                    output.push_str("██");
                } else {
                    output.push_str("  ");
                }
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
