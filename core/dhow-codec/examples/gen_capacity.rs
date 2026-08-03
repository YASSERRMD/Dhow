//! Emits the measured QR capacity table as Markdown.
//!
//! Run via `scripts/gen_qr_capacity.sh`. The numbers come from the encoder
//! itself, so the committed table cannot drift from what dhow will accept.

use dhow_codec::qr::{Ecc, MAX_VERSION, MIN_VERSION, capacity, max_symbol_size};

fn main() {
    println!("# QR Capacity Table");
    println!();
    println!("> GENERATED FILE. Do not edit by hand.");
    println!("> Regenerate with `scripts/gen_qr_capacity.sh`.");
    println!();
    println!("Bytes that fit in one QR code, and the largest codec symbol size that");
    println!("leaves room for a 46-byte frame header and a 4-byte RaptorQ payload");
    println!("identifier. Measured against the encoder, not transcribed from the");
    println!("specification: a hand-copied table can be optimistic by a byte, and that");
    println!("fails only for the frames that fill a version exactly.");
    println!();
    println!("A dash means the version is too small to hold even a frame header.");
    println!();
    println!(
        "| Version | Modules | L bytes | L symbol | M bytes | M symbol | Q bytes | Q symbol | H bytes | H symbol |"
    );
    println!(
        "|--------:|--------:|--------:|---------:|--------:|---------:|--------:|---------:|--------:|---------:|"
    );

    for v in MIN_VERSION..=MAX_VERSION {
        let modules = 17 + 4 * v as usize;
        let mut cells = String::new();
        for ecc in [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High] {
            let cap = capacity(v, ecc).expect("valid version");
            let sym = match max_symbol_size(v, ecc).expect("valid version") {
                Some(s) => s.to_string(),
                None => "-".to_string(),
            };
            cells.push_str(&format!(" {cap} | {sym} |"));
        }
        println!("| {v} | {modules} |{cells}");
    }
}
