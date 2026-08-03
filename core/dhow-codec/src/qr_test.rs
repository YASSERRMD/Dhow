//! Tests for QR frame encoding.

use crate::qr::*;

const LEVELS: [Ecc; 4] = [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High];

// --- Capacity ---

#[test]
fn test_capacity_is_exact_at_the_boundary() {
    // The measured capacity must be the true maximum: one byte more must not
    // encode. A capacity that is optimistic by a byte would fail only for the
    // frames that happen to fill a version exactly, which is the worst kind of
    // intermittent bug.
    for version in [1u8, 5, 10, 20, 40] {
        for ecc in LEVELS {
            let cap = capacity(version, ecc).unwrap();
            assert!(
                QrCodeEncoder::encode_at(&vec![0u8; cap], version, ecc).is_ok(),
                "version {version} {ecc:?}: capacity {cap} did not encode"
            );
            assert!(
                QrCodeEncoder::encode_at(&vec![0u8; cap + 1], version, ecc).is_err(),
                "version {version} {ecc:?}: capacity {cap} was one byte short"
            );
        }
    }
}

#[test]
fn test_capacity_grows_with_version() {
    for ecc in LEVELS {
        for version in MIN_VERSION..MAX_VERSION {
            let smaller = capacity(version, ecc).unwrap();
            let larger = capacity(version + 1, ecc).unwrap();
            assert!(
                larger > smaller,
                "{ecc:?}: version {} held {smaller}, version {} held {larger}",
                version,
                version + 1
            );
        }
    }
}

#[test]
fn test_capacity_shrinks_as_error_correction_rises() {
    // More recovery capability costs payload; that trade is the whole reason
    // the level is configurable.
    for version in [1u8, 10, 25, 40] {
        let l = capacity(version, Ecc::Low).unwrap();
        let m = capacity(version, Ecc::Medium).unwrap();
        let q = capacity(version, Ecc::Quartile).unwrap();
        let h = capacity(version, Ecc::High).unwrap();
        assert!(
            l > m && m > q && q > h,
            "version {version}: {l} {m} {q} {h}"
        );
    }
}

#[test]
fn test_capacity_rejects_versions_outside_the_range() {
    for version in [0u8, 41, 255] {
        assert!(matches!(
            capacity(version, Ecc::Medium),
            Err(QrError::InvalidVersion { .. })
        ));
    }
}

#[test]
fn test_max_symbol_size_leaves_room_for_the_frame_header() {
    // A frame is a 46-byte header plus a 4-byte payload identifier plus the
    // symbol, and the whole thing must fit one QR code.
    for version in [10u8, 20, 40] {
        let ecc = Ecc::Medium;
        let symbol = max_symbol_size(version, ecc).unwrap().unwrap() as usize;
        let cap = capacity(version, ecc).unwrap();
        assert_eq!(symbol + crate::frame::FRAME_HEADER_SIZE + 4, cap);
    }
}

#[test]
fn test_max_symbol_size_reports_versions_that_are_too_small() {
    // Version 1 at high error correction cannot hold even a frame header.
    assert!(max_symbol_size(1, Ecc::High).unwrap().is_none());
}

#[test]
fn test_smallest_version_for_picks_the_smallest_that_fits() {
    for ecc in LEVELS {
        for len in [1usize, 50, 200, 1000] {
            let Some(v) = smallest_version_for(len, ecc) else {
                continue;
            };
            assert!(capacity(v, ecc).unwrap() >= len);
            if v > MIN_VERSION {
                assert!(
                    capacity(v - 1, ecc).unwrap() < len,
                    "{ecc:?}: version {} would also have held {len}",
                    v - 1
                );
            }
        }
    }
}

#[test]
fn test_smallest_version_for_reports_impossible_sizes() {
    assert!(smallest_version_for(100_000, Ecc::Low).is_none());
}

// --- Encoding ---

#[test]
fn test_encode_round_trips_through_the_module_grid() {
    let data = b"a wire frame";
    let qr = QrCodeEncoder::encode(data).unwrap();
    let modules = qr.to_modules();

    assert_eq!(modules.len(), qr.size() * qr.size());
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            assert_eq!(modules[y * qr.size() + x], u8::from(qr.get_module(x, y)));
        }
    }
}

#[test]
fn test_encoding_is_deterministic() {
    // The sender loops a frame stream on screen, so every rendering of a frame
    // must be identical or the receiver cannot treat captures as
    // interchangeable.
    let data = b"deterministic frame content";
    let a = QrCodeEncoder::encode_at(data, 10, Ecc::Medium).unwrap();
    let b = QrCodeEncoder::encode_at(data, 10, Ecc::Medium).unwrap();
    assert_eq!(a.to_modules(), b.to_modules());
    assert_eq!(a.size(), b.size());
}

#[test]
fn test_encode_at_pins_the_version() {
    // A stream whose frames changed size mid-transfer would force the receiver
    // to re-acquire focus and framing on each change.
    for version in [5u8, 15, 30] {
        let qr = QrCodeEncoder::encode_at(b"short", version, Ecc::Medium).unwrap();
        assert_eq!(qr.version(), version);
        assert_eq!(qr.size(), 17 + 4 * version as usize);
    }
}

#[test]
fn test_encode_at_rejects_oversized_data() {
    let cap = capacity(5, Ecc::Medium).unwrap();
    assert!(matches!(
        QrCodeEncoder::encode_at(&vec![0u8; cap + 1], 5, Ecc::Medium),
        Err(QrError::DataTooLong { .. })
    ));
}

#[test]
fn test_encode_at_rejects_invalid_versions() {
    for version in [0u8, 41] {
        assert!(matches!(
            QrCodeEncoder::encode_at(b"x", version, Ecc::Medium),
            Err(QrError::InvalidVersion { .. })
        ));
    }
}

#[test]
fn test_encode_reports_the_level_it_used() {
    for ecc in LEVELS {
        let qr = QrCodeEncoder::encode_with(b"frame", ecc).unwrap();
        assert_eq!(qr.ecc(), ecc);
    }
}

#[test]
fn test_encode_handles_a_realistic_frame() {
    // A full frame at version 20 medium: header, payload id, and symbol.
    let ecc = Ecc::Medium;
    let version = 20u8;
    let symbol = max_symbol_size(version, ecc).unwrap().unwrap() as usize;
    let frame = vec![0xA5u8; crate::frame::FRAME_HEADER_SIZE + 4 + symbol];

    let qr = QrCodeEncoder::encode_at(&frame, version, ecc).unwrap();
    assert_eq!(qr.version(), version);
}

#[test]
fn test_encode_handles_binary_data_with_nulls_and_high_bytes() {
    let data: Vec<u8> = (0..=255u8).collect();
    let qr = QrCodeEncoder::encode(&data).unwrap();
    assert!(qr.size() > 0);
}

#[test]
fn test_encode_single_byte() {
    let qr = QrCodeEncoder::encode(&[0x42]).unwrap();
    assert!(qr.size() >= 21);
}

#[test]
fn test_encode_empty_data() {
    // An empty frame is not something the codec produces, but the encoder must
    // not panic on one.
    let qr = QrCodeEncoder::encode(&[]).unwrap();
    assert!(qr.size() >= 21);
}

#[test]
fn test_encode_rejects_data_beyond_any_version() {
    assert!(QrCodeEncoder::encode(&vec![0u8; 100_000]).is_err());
}

// --- Rendering ---

#[test]
fn test_terminal_rendering_has_correct_dimensions() {
    let qr = QrCodeEncoder::encode(b"render me").unwrap();
    let text = qr.to_terminal();
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines.len(), qr.size());
    for line in lines {
        // Two characters per module, so a square code stays square on a
        // terminal whose cells are twice as tall as they are wide.
        assert_eq!(line.chars().count(), qr.size() * 2);
    }
}

#[test]
fn test_module_reads_outside_the_grid_are_light() {
    // A renderer walking a quiet zone should not need a bounds check.
    let qr = QrCodeEncoder::encode(b"quiet zone").unwrap();
    let n = qr.size();
    assert!(!qr.get_module(n, 0));
    assert!(!qr.get_module(0, n));
    assert!(!qr.get_module(n * 2, n * 2));
}

// --- Error-correction level names ---

#[test]
fn test_ecc_letters_round_trip() {
    for ecc in LEVELS {
        assert_eq!(Ecc::from_letter(ecc.letter()), Some(ecc));
    }
}

#[test]
fn test_ecc_letters_are_case_insensitive() {
    assert_eq!(Ecc::from_letter('m'), Some(Ecc::Medium));
    assert_eq!(Ecc::from_letter('M'), Some(Ecc::Medium));
}

#[test]
fn test_ecc_rejects_unknown_letters() {
    for c in ['X', '1', ' ', 'z'] {
        assert!(Ecc::from_letter(c).is_none(), "{c} was accepted");
    }
}

#[test]
fn test_ecc_default_is_medium() {
    assert_eq!(Ecc::default(), Ecc::Medium);
}
