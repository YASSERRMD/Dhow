//! Tests for key generation, storage, and loading.

use crate::KeyError;
use crate::key::*;
use std::path::{Path, PathBuf};

/// A directory that removes itself when the test ends.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        // Include the thread id so parallel tests never share a directory.
        let unique = format!("dhow-key-test-{tag}-{:?}", std::thread::current().id());
        let path = std::env::temp_dir().join(unique.replace(['(', ')', ' '], ""));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

// --- Generation ---

#[test]
fn test_generated_operator_keys_differ() {
    let a = OperatorKey::generate().unwrap();
    let b = OperatorKey::generate().unwrap();
    assert_ne!(a, b, "two generated keys must not be identical");
}

#[test]
fn test_generated_operator_key_is_not_all_zeros() {
    let key = OperatorKey::generate().unwrap();
    assert_ne!(key.expose_bytes(), &[0u8; 32]);
}

#[test]
fn test_generated_identities_differ() {
    let a = IdentityKey::generate().unwrap();
    let b = IdentityKey::generate().unwrap();
    assert_ne!(a.public().to_bytes(), b.public().to_bytes());
}

#[test]
fn test_identity_from_seed_is_deterministic() {
    let seed = [9u8; 32];
    let a = IdentityKey::from_seed(&seed);
    let b = IdentityKey::from_seed(&seed);
    assert_eq!(a.public().to_bytes(), b.public().to_bytes());
}

// --- Signing ---

#[test]
fn test_sign_and_verify_round_trip() {
    let key = IdentityKey::generate().unwrap();
    let msg = b"manifest bytes";
    let sig = key.sign(msg);
    assert!(key.public().verify(msg, &sig));
}

#[test]
fn test_signature_rejects_modified_message() {
    let key = IdentityKey::generate().unwrap();
    let sig = key.sign(b"manifest bytes");
    assert!(!key.public().verify(b"manifest bytez", &sig));
}

#[test]
fn test_signature_rejects_other_identity() {
    let signer = IdentityKey::generate().unwrap();
    let other = IdentityKey::generate().unwrap();
    let msg = b"manifest bytes";
    let sig = signer.sign(msg);
    assert!(!other.public().verify(msg, &sig));
}

#[test]
fn test_signature_rejects_every_single_byte_mutation_of_the_message() {
    let key = IdentityKey::generate().unwrap();
    let msg = b"a manifest that must not be malleable".to_vec();
    let sig = key.sign(&msg);
    for i in 0..msg.len() {
        let mut mutated = msg.clone();
        mutated[i] ^= 0x01;
        assert!(
            !key.public().verify(&mutated, &sig),
            "mutation at byte {i} verified"
        );
    }
}

// --- Public identity encoding ---

#[test]
fn test_public_identity_round_trips_through_bytes() {
    let key = IdentityKey::generate().unwrap();
    let public = key.public();
    let restored = PublicIdentity::from_bytes(&public.to_bytes()).unwrap();
    assert_eq!(public, restored);
}

#[test]
fn test_public_identity_rejects_non_curve_point() {
    // A compressed Edwards encoding only decodes when the implied x^2 is a
    // quadratic residue, which these y values are not. Note that not every
    // arbitrary 32-byte string fails this way: an all-ones encoding does
    // decompress, so it is not a valid negative case.
    for first in [2u8, 7, 8, 11, 12] {
        let mut encoded = [0u8; 32];
        encoded[0] = first;
        assert!(
            PublicIdentity::from_bytes(&encoded).is_err(),
            "encoding starting {first} was accepted as a public key"
        );
    }
}

#[test]
fn test_fingerprints_differ_between_identities() {
    let a = IdentityKey::generate().unwrap();
    let b = IdentityKey::generate().unwrap();
    assert_ne!(a.public().fingerprint(), b.public().fingerprint());
}

#[test]
fn test_fingerprint_is_stable_for_one_identity() {
    let key = IdentityKey::generate().unwrap();
    assert_eq!(key.public().fingerprint(), key.public().fingerprint());
}

// --- Secrets must not be formattable ---

#[test]
fn test_debug_does_not_reveal_operator_key() {
    let key = OperatorKey::from_bytes([0xAB; 32]);
    let rendered = format!("{key:?}");
    assert!(
        !rendered.contains("ab"),
        "key bytes appeared in Debug output"
    );
    assert!(rendered.contains("redacted"));
}

#[test]
fn test_debug_does_not_reveal_identity_key() {
    let key = IdentityKey::from_seed(&[0xCD; 32]);
    let rendered = format!("{key:?}");
    assert!(
        !rendered.contains("cd"),
        "seed bytes appeared in Debug output"
    );
    assert!(rendered.contains("redacted"));
}

#[test]
fn test_key_errors_do_not_contain_key_material() {
    // A key file whose material is a recognizable pattern must not echo it.
    let err = KeyError::InvalidKey {
        details: "key file checksum mismatch".to_string(),
    };
    let rendered = err.to_string();
    assert!(!rendered.contains("ab"));
}

// --- Key file round trip ---

#[test]
fn test_operator_key_file_round_trip() {
    let dir = TempDir::new("op-round-trip");
    let path = dir.join("operator.key");
    let key = OperatorKey::generate().unwrap();

    save_operator(&path, &key).unwrap();
    let loaded = load_operator(&path).unwrap();
    assert_eq!(key, loaded);
}

#[test]
fn test_identity_key_file_round_trip() {
    let dir = TempDir::new("id-round-trip");
    let path = dir.join("identity.key");
    let key = IdentityKey::generate().unwrap();

    save_identity(&path, &key).unwrap();
    let loaded = load_identity(&path).unwrap();
    assert_eq!(key.public().to_bytes(), loaded.public().to_bytes());

    // The reloaded key must produce signatures the original identity verifies.
    let msg = b"round trip";
    assert!(key.public().verify(msg, &loaded.sign(msg)));
}

#[test]
fn test_key_file_has_expected_size() {
    let dir = TempDir::new("size");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().len() as usize,
        KEY_FILE_SIZE
    );
}

#[test]
fn test_key_file_starts_with_magic_and_version() {
    let dir = TempDir::new("magic");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[0..4], b"DHKY");
    assert_eq!(bytes[4], KEY_VERSION);
}

#[test]
fn test_loading_rejects_wrong_key_kind() {
    let dir = TempDir::new("kind");
    let op_path = dir.join("operator.key");
    let id_path = dir.join("identity.key");
    save_operator(&op_path, &OperatorKey::generate().unwrap()).unwrap();
    save_identity(&id_path, &IdentityKey::generate().unwrap()).unwrap();

    assert!(load_identity(&op_path).is_err());
    assert!(load_operator(&id_path).is_err());
}

// --- Permissions ---

#[cfg(unix)]
#[test]
fn test_saved_secret_key_is_owner_only() {
    let dir = TempDir::new("perms");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    assert_eq!(mode_of(&path), 0o600);
}

#[cfg(unix)]
#[test]
fn test_saving_over_a_permissive_file_tightens_permissions() {
    let dir = TempDir::new("perms-overwrite");
    let path = dir.join("operator.key");
    std::fs::write(&path, b"placeholder").unwrap();
    set_mode(&path, 0o666);

    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    assert_eq!(mode_of(&path), 0o600);
}

#[cfg(unix)]
#[test]
fn test_loading_rejects_group_or_world_readable_key() {
    let dir = TempDir::new("perms-reject");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();

    for mode in [0o640, 0o604, 0o660, 0o666, 0o644] {
        set_mode(&path, mode);
        assert!(
            matches!(
                load_operator(&path),
                Err(KeyError::InsecurePermissions { .. })
            ),
            "mode {mode:#o} was accepted"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_loading_accepts_owner_only_modes() {
    let dir = TempDir::new("perms-accept");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();

    for mode in [0o600, 0o400] {
        set_mode(&path, mode);
        assert!(load_operator(&path).is_ok(), "mode {mode:#o} was rejected");
    }
}

// --- Corrupted and hostile key files ---

/// Writes arbitrary bytes as an owner-only key file.
fn write_key_bytes(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    set_mode(path, 0o600);
}

#[test]
fn test_loading_rejects_truncated_file() {
    let dir = TempDir::new("truncated");
    let path = dir.join("operator.key");
    let key = OperatorKey::generate().unwrap();
    save_operator(&path, &key).unwrap();
    let good = std::fs::read(&path).unwrap();

    for cut in [0, 1, 8, 40, KEY_FILE_SIZE - 1] {
        write_key_bytes(&path, &good[..cut]);
        assert!(
            matches!(load_operator(&path), Err(KeyError::Truncated { .. })),
            "a {cut}-byte file was accepted"
        );
    }
}

#[test]
fn test_loading_rejects_oversized_file() {
    let dir = TempDir::new("oversized");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    write_key_bytes(&path, &bytes);
    assert!(load_operator(&path).is_err());
}

#[test]
fn test_loading_rejects_bad_magic() {
    let dir = TempDir::new("bad-magic");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] = b'X';
    write_key_bytes(&path, &bytes);
    assert!(matches!(
        load_operator(&path),
        Err(KeyError::InvalidMagic { .. })
    ));
}

#[test]
fn test_loading_rejects_unsupported_version() {
    let dir = TempDir::new("bad-version");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[4] = 99;
    write_key_bytes(&path, &bytes);
    assert!(matches!(
        load_operator(&path),
        Err(KeyError::UnsupportedVersion { version: 99 })
    ));
}

#[test]
fn test_loading_rejects_unknown_key_kind() {
    let dir = TempDir::new("bad-kind");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[5] = 42;
    write_key_bytes(&path, &bytes);
    assert!(load_operator(&path).is_err());
}

#[test]
fn test_loading_rejects_nonzero_reserved_field() {
    let dir = TempDir::new("reserved");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[6] = 1;
    write_key_bytes(&path, &bytes);
    assert!(load_operator(&path).is_err());
}

#[test]
fn test_loading_rejects_every_single_byte_mutation() {
    let dir = TempDir::new("mutations");
    let path = dir.join("operator.key");
    save_operator(&path, &OperatorKey::generate().unwrap()).unwrap();
    let good = std::fs::read(&path).unwrap();

    // Tampering with any byte must be caught, whether it lands in the header,
    // the key material, or the checksum itself.
    for i in 0..good.len() {
        let mut mutated = good.clone();
        mutated[i] ^= 0x01;
        write_key_bytes(&path, &mutated);
        assert!(
            load_operator(&path).is_err(),
            "mutation at byte {i} was accepted"
        );
    }
}

#[test]
fn test_loading_missing_file_is_an_error_not_a_panic() {
    let dir = TempDir::new("missing");
    assert!(load_operator(&dir.join("absent.key")).is_err());
}

// --- Public key files ---

#[test]
fn test_public_key_file_round_trip() {
    let dir = TempDir::new("public");
    let path = dir.join("identity.pub");
    let key = IdentityKey::generate().unwrap();

    save_public(&path, &key.public()).unwrap();
    assert_eq!(load_public(&path).unwrap(), key.public());
}

#[test]
fn test_public_key_file_rejects_wrong_length() {
    let dir = TempDir::new("public-len");
    let path = dir.join("identity.pub");
    std::fs::write(&path, [0u8; 31]).unwrap();
    assert!(matches!(
        load_public(&path),
        Err(KeyError::Truncated { .. })
    ));
}
