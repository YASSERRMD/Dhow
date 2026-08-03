//! A reference encoder and decoder driven through the Rust library API.
//!
//! This exists so the Go-driven FFI path has something to be differentially
//! tested *against*. Go calls `dhow_encoder_new` and friends across a C ABI,
//! marshalling pointers and lengths through cgo; this binary reaches the same
//! functions directly, with no boundary in between. If the two disagree about a
//! single byte, the disagreement is in the boundary.
//!
//! It deliberately does **not** call any `extern "C"` function. A differential
//! test whose two sides share the code under test proves nothing.
//!
//! # What it does not test
//!
//! The two sides run the same encoding logic, so this is a *boundary*
//! differential and not an *implementation* one: it cannot catch a bug in
//! RaptorQ or in the AEAD, only a bug in how bytes cross the ABI. That is worth
//! saying plainly, because a differential test is easy to mistake for a stronger
//! guarantee than it gives. The properties of the encoding itself are covered by
//! the property tests in `dhow-codec` and `dhow-crypt`.
//!
//! # Protocol
//!
//! Line-oriented, so neither side needs a JSON dependency and a mismatch is
//! readable in a diff. One job per input line, whitespace-separated:
//!
//! ```text
//! <key_path> <session_id_hex> <salt_hex> <nonce_hex> \
//!     <symbol_size> <block_count> <source_per_block> <total_per_block> <payload_hex>
//! ```
//!
//! The operator key arrives as a **path to a key file**, not as hex. That is not
//! a convenience: no function in this library's ABI takes raw key bytes, so the
//! Go side of the comparison cannot produce them, and a reference that demanded
//! them would have forced a hole in exactly the property the ABI exists to keep.
//! Both sides load the same file.
//!
//! The line is whitespace-separated, so a key path containing a space is not
//! supported. Test directories do not have them.
//!
//! An empty payload is written as `-`, because an empty field would collapse the
//! whitespace split.
//!
//! Output per job:
//!
//! ```text
//! job <index>
//! size <ciphertext length>
//! digest <hex>
//! frames <count>
//! frame <hex>
//! ...
//! decoded <plaintext hex, or - when empty>
//! end
//! ```
//!
//! A job that fails writes `error <message>` in place of everything after `job`.

use dhow_codec::blake3::blake3_digest;
use dhow_codec::pipeline::{Pipeline, PipelineDecoder};
use dhow_codec::session::{RaptorQParams, SessionParams};
use dhow_crypt::aead::{Nonce, TransferKeys, decrypt_payload, encrypt_payload};
use dhow_crypt::kdf::Salt;
use dhow_crypt::key::load_operator;
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::BufReader::new(io::stdin());
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for (index, line) in stdin.lines().enumerate() {
        let line = line.expect("reading a job line");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        writeln!(out, "job {index}").unwrap();
        match run_job(line) {
            Ok(result) => {
                writeln!(out, "size {}", result.payload_size).unwrap();
                writeln!(out, "digest {}", hex(&result.payload_digest)).unwrap();
                writeln!(out, "frames {}", result.frames.len()).unwrap();
                for frame in &result.frames {
                    writeln!(out, "frame {}", hex(frame)).unwrap();
                }
                writeln!(out, "decoded {}", hex_or_dash(&result.decoded)).unwrap();
            }
            Err(message) => writeln!(out, "error {message}").unwrap(),
        }
        writeln!(out, "end").unwrap();
    }

    out.flush().unwrap();
}

struct JobResult {
    payload_size: u64,
    payload_digest: [u8; 32],
    frames: Vec<Vec<u8>>,
    decoded: Vec<u8>,
}

fn run_job(line: &str) -> Result<JobResult, String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() != 9 {
        return Err(format!("expected 9 fields, got {}", fields.len()));
    }

    let key_path = std::path::Path::new(fields[0]);
    let session_id: [u8; 16] = fixed(fields[1], "session id")?;
    let salt: [u8; 32] = fixed(fields[2], "salt")?;
    let nonce: [u8; 24] = fixed(fields[3], "nonce")?;
    let symbol_size: u32 = fields[4].parse().map_err(|_| "bad symbol size".to_string())?;
    let block_count: u32 = fields[5].parse().map_err(|_| "bad block count".to_string())?;
    let source: u32 = fields[6]
        .parse()
        .map_err(|_| "bad source symbol count".to_string())?;
    let total: u32 = fields[7]
        .parse()
        .map_err(|_| "bad total symbol count".to_string())?;
    let payload = if fields[8] == "-" {
        Vec::new()
    } else {
        unhex(fields[8]).map_err(|e| format!("bad payload: {e}"))?
    };

    // Exactly what dhow_encoder_new does, through the library rather than the
    // ABI. The order matters: derive, encrypt, then take the size and digest
    // from the ciphertext, because framing operates on ciphertext.
    let key = load_operator(key_path).map_err(|e| format!("loading {}: {e}", key_path.display()))?;
    let keys = TransferKeys::derive(&key, &Salt::from_bytes(salt)).map_err(|e| e.to_string())?;
    let ciphertext = encrypt_payload(
        &keys,
        &Nonce::from_bytes(nonce),
        &session_id,
        &payload,
    )
    .map_err(|e| e.to_string())?;

    let params = SessionParams {
        payload_size: ciphertext.len() as u64,
        block_count,
        symbol_size,
        source_symbols_per_block: source,
        total_symbols_per_block: total,
        // The ABI does not expose these, so it always sends 1/1/1. Matching
        // that here is the point: the reference must describe the same session.
        raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
        payload_digest: blake3_digest(&ciphertext),
    };

    let pipeline =
        Pipeline::new(session_id, params, *keys.session_key()).map_err(|e| e.to_string())?;
    let frames = pipeline
        .encode_to_bytes(&ciphertext)
        .map_err(|e| e.to_string())?;

    // Decode it back through the library too, so the test can compare the
    // decoded plaintext and not only the frames.
    let mut decoder =
        PipelineDecoder::new(session_id, params, *keys.session_key()).map_err(|e| e.to_string())?;
    for frame in &frames {
        // A rejected frame is not an error here: the decoder stops accepting
        // once it has enough, and the encoder emits repair symbols beyond that.
        let _ = decoder.accept(frame);
    }
    let recovered = decoder.finish().map_err(|e| e.to_string())?;
    let decoded = decrypt_payload(
        &keys,
        &Nonce::from_bytes(nonce),
        &session_id,
        &recovered,
    )
    .map_err(|e| e.to_string())?;

    Ok(JobResult {
        payload_size: params.payload_size,
        payload_digest: params.payload_digest,
        frames,
        decoded,
    })
}

fn fixed<const N: usize>(field: &str, what: &str) -> Result<[u8; N], String> {
    let bytes = unhex(field).map_err(|e| format!("bad {what}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{what} must be {N} bytes"))
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_or_dash(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "-".to_string()
    } else {
        hex(bytes)
    }
}
