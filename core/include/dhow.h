/*
 * dhow.h - C ABI for the Dhow air-gapped data courier.
 *
 * GENERATED FILE. Do not edit by hand.
 * Regenerate with scripts/gen_header.sh after changing dhow-ffi.
 *
 * Conventions:
 *   - Every function returns DhowStatus (0 ok, negative on failure), or a
 *     handle that is NULL on failure.
 *   - Handles are opaque and must be released with the matching _free.
 *     Passing NULL to a _free is a no-op.
 *   - Buffers are caller-allocated. Call with a NULL buffer to learn the
 *     required size, then call again with a buffer at least that large.
 *   - No function accepts or returns raw secret key material.
 */

#ifndef DHOW_H
#define DHOW_H



#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * ABI version of this library.
 *
 * Bumped whenever the C surface changes in a way that is not backwards
 * compatible. A caller that links against a mismatched version should refuse
 * to run rather than guess.
 */
#define DHOW_ABI_VERSION 4

/**
 * Status returned by every `dhow_*` entry point.
 *
 * `Ok` is zero and every failure is negative, so callers can test `< 0`.
 */
typedef enum {
    /**
     * The call succeeded.
     */
    DHOW_STATUS_OK = 0,
    /**
     * A required pointer argument was null.
     */
    DHOW_STATUS_NULL_ARGUMENT = -1,
    /**
     * An argument was outside its permitted range.
     */
    DHOW_STATUS_INVALID_ARGUMENT = -2,
    /**
     * A supplied buffer was too small; no bytes were written.
     */
    DHOW_STATUS_BUFFER_TOO_SMALL = -3,
    /**
     * The session parameters were rejected.
     */
    DHOW_STATUS_INVALID_PARAMETERS = -4,
    /**
     * A frame failed parsing, authentication, or its integrity checks.
     */
    DHOW_STATUS_FRAME_REJECTED = -5,
    /**
     * The decoder does not yet hold enough symbols.
     */
    DHOW_STATUS_INCOMPLETE = -6,
    /**
     * A digest, MAC, or signature check failed.
     */
    DHOW_STATUS_VERIFICATION_FAILED = -7,
    /**
     * Encryption or decryption failed.
     */
    DHOW_STATUS_CRYPTO_FAILED = -8,
    /**
     * Key generation, loading, or storage failed.
     */
    DHOW_STATUS_KEY_FAILED = -9,
    /**
     * An internal error occurred.
     */
    DHOW_STATUS_INTERNAL = -10,
    /**
     * A panic was caught at the ABI boundary. Always a bug in this library.
     */
    DHOW_STATUS_PANIC = -11,
    /**
     * A resume state was malformed, or did not describe the journal replayed
     * against it.
     *
     * Distinct from [`DhowStatus::VerificationFailed`] because the two mean
     * opposite things to an operator: a failed verification says the transfer
     * is bad, while a rejected resume says only that the saved progress is
     * unusable and the transfer can be restarted.
     */
    DHOW_STATUS_RESUME_REJECTED = -12,
} DhowStatus;

/**
 * An opaque frame decoder.
 */
typedef struct DhowDecoder DhowDecoder;

/**
 * An opaque frame encoder.
 */
typedef struct DhowEncoder DhowEncoder;

/**
 * An opaque streaming BLAKE3 hasher.
 */
typedef struct DhowHasher DhowHasher;

/**
 * An opaque Ed25519 identity keypair.
 */
typedef struct DhowIdentity DhowIdentity;

/**
 * An opaque operator key.
 */
typedef struct DhowKey DhowKey;

/**
 * An opaque manifest.
 *
 * A handle of this type is only ever produced by building one from an identity
 * or by verifying one against a public identity, so possession of the handle
 * means the signature was checked. There is no way to obtain one by parsing
 * alone.
 */
typedef struct DhowManifest DhowManifest;

/**
 * An opaque Ed25519 public identity.
 */
typedef struct DhowPublicIdentity DhowPublicIdentity;

/**
 * Session parameters as they cross the ABI.
 *
 * A plain `#[repr(C)]` struct rather than a handle: these are public
 * parameters the caller composes and inspects, and passing them by value
 * avoids a getter for every field.
 */
typedef struct {
    /**
     * Size of the encrypted payload in bytes.
     */
    uint64_t payload_size;
    /**
     * Number of source blocks.
     */
    uint32_t block_count;
    /**
     * Symbol size in bytes.
     */
    uint32_t symbol_size;
    /**
     * Source symbols per block.
     */
    uint32_t source_symbols_per_block;
    /**
     * Total symbols per block, including repair.
     */
    uint32_t total_symbols_per_block;
    /**
     * BLAKE3 digest of the encrypted payload.
     */
    uint8_t payload_digest[32];
} DhowSessionParams;

/**
 * One file's inventory entry as it crosses the ABI.
 *
 * The awkward part of this boundary is that a manifest's inventory is
 * variable-length in two dimensions: a variable number of entries, each with a
 * variable-length name. Going in, the caller composes an array of these and
 * passes a pointer and a count; the names are borrowed for the duration of the
 * call and nothing here retains them.
 *
 * Coming out, there is no array: a verified manifest is a handle and its
 * entries are read one at a time through the indexed accessors below. Handing
 * back an array would mean handing back allocations the caller must free with
 * an allocator it does not own, which is the one thing this ABI never does.
 */
typedef struct {
    /**
     * NUL-terminated UTF-8 name, relative and `/`-separated.
     */
    const char *name;
    /**
     * File size in bytes.
     */
    uint64_t size;
    /**
     * BLAKE3 digest of the file's contents.
     */
    uint8_t digest[32];
    /**
     * Non-zero if the owner execute bit was set.
     */
    uint8_t executable;
    /**
     * Reserved; must be zero. Present so the struct's size and alignment do
     * not change when a future flag is added.
     */
    uint8_t reserved[7];
} DhowFileEntry;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Returns the ABI version this library was built with.
 */
uint32_t dhow_abi_version(void);

/**
 * Returns the crate version as a static NUL-terminated string.
 *
 * The pointer is valid for the lifetime of the process and must not be freed.
 */
const char *dhow_version_string(void);

/**
 * Copies the current thread's last error message into `buf` as a
 * NUL-terminated C string.
 *
 * Returns the number of bytes written including the terminator, or a negative
 * [`DhowStatus`] on failure. Pass a null `buf` to query the required size,
 * which is returned as a positive count.
 *
 * # Safety
 *
 * `buf` must either be null or point to at least `len` writable bytes. The
 * caller owns the buffer; this function never allocates on the caller's
 * behalf and never retains the pointer.
 */
int dhow_last_error_message(char *buf, uintptr_t len);

/**
 * Returns a static, NUL-terminated description of a status code.
 *
 * The returned pointer is valid for the lifetime of the process and must not
 * be freed by the caller.
 */
const char *dhow_status_string(int status);

/**
 * Generates a new operator key.
 *
 * Returns null on failure; the key material never crosses the boundary.
 */
DhowKey *dhow_key_generate(void);

/**
 * Loads an operator key from a key file.
 *
 * Fails if the file is missing, malformed, or readable by anyone but its
 * owner. Returns null on failure.
 *
 * # Safety
 *
 * `path` must be a NUL-terminated C string.
 */
DhowKey *dhow_key_load(const char *path);

/**
 * Writes an operator key to a key file with owner-only permissions.
 *
 * # Safety
 *
 * `key` must be a live handle and `path` a NUL-terminated C string.
 */
DhowStatus dhow_key_save(const DhowKey *key, const char *path);

/**
 * Releases a key handle. Passing null is a no-op.
 *
 * # Safety
 *
 * `key` must be null or a handle from this library that has not been freed.
 */
void dhow_key_free(DhowKey *key);

/**
 * Encrypts `payload` and builds the full frame stream for a session.
 *
 * The encoder holds every frame, so [`dhow_encoder_frame_count`] and
 * [`dhow_encoder_frame`] can serve them in any order and as many times as the
 * sender needs, which is what a repeating display loop requires.
 *
 * # Safety
 *
 * `key` must be a live handle; `session_id` and `salt` must point to 16 and 32
 * readable bytes; `payload` must point to `payload_len` readable bytes.
 */
DhowEncoder *dhow_encoder_new(const DhowKey *key,
                              const uint8_t *session_id,
                              const uint8_t *salt,
                              const uint8_t *nonce,
                              DhowSessionParams params_in,
                              const uint8_t *payload,
                              uintptr_t payload_len);

/**
 * Returns the session parameters the encoder actually used.
 *
 * The caller supplies a payload size and digest describing the *plaintext*,
 * but framing operates on ciphertext, which is longer by the AEAD tag. The
 * encoder recomputes both and reports them here, because these are the values
 * that must travel in the signed manifest for a receiver to configure its
 * decoder. Without this the caller would have to reimplement the length and
 * digest rules to fill in the manifest.
 *
 * # Safety
 *
 * `encoder` must be a live handle and `out` must point to a writable
 * [`DhowSessionParams`].
 */
DhowStatus dhow_encoder_params(const DhowEncoder *encoder, DhowSessionParams *out);

/**
 * Returns the number of frames the encoder holds, or a negative status.
 *
 * # Safety
 *
 * `encoder` must be null or a live handle.
 */
int dhow_encoder_frame_count(const DhowEncoder *encoder);

/**
 * Copies frame `index` into `buf`.
 *
 * Call with a null `buf` to learn the frame's size, which is reported through
 * `written`.
 *
 * # Safety
 *
 * `encoder` must be a live handle; `buf` must be null or point to `len`
 * writable bytes; `written` must be null or writable.
 */
DhowStatus dhow_encoder_frame(const DhowEncoder *encoder,
                              uintptr_t index,
                              uint8_t *buf,
                              uintptr_t len,
                              uintptr_t *written);

/**
 * Releases an encoder handle. Passing null is a no-op.
 *
 * # Safety
 *
 * `encoder` must be null or a handle from this library that has not been
 * freed.
 */
void dhow_encoder_free(DhowEncoder *encoder);

/**
 * Creates a decoder for a session.
 *
 * # Safety
 *
 * `key` must be a live handle; `session_id` and `salt` must point to 16 and 32
 * readable bytes.
 */
DhowDecoder *dhow_decoder_new(const DhowKey *key,
                              const uint8_t *session_id,
                              const uint8_t *salt,
                              DhowSessionParams params);

/**
 * Feeds one captured frame to the decoder.
 *
 * A rejected frame returns [`DhowStatus::FrameRejected`] and leaves the
 * decoder unchanged. A receiver watching a screen should keep going rather
 * than treat this as fatal: most rejections are ordinary capture noise.
 *
 * # Safety
 *
 * `decoder` must be a live handle and `frame` must point to `len` readable
 * bytes.
 */
DhowStatus dhow_decoder_accept(DhowDecoder *decoder, const uint8_t *frame, uintptr_t len);

/**
 * Returns 1 when every block has decoded, 0 when not, or a negative status.
 *
 * # Safety
 *
 * `decoder` must be null or a live handle.
 */
int dhow_decoder_is_complete(const DhowDecoder *decoder);

/**
 * Returns how many blocks have decoded, or a negative status.
 *
 * # Safety
 *
 * `decoder` must be null or a live handle.
 */
int dhow_decoder_blocks_complete(const DhowDecoder *decoder);

/**
 * Reassembles, verifies, and decrypts the payload.
 *
 * Returns [`DhowStatus::Incomplete`] while blocks are outstanding, and
 * [`DhowStatus::VerificationFailed`] if the reassembled ciphertext does not
 * match the digest the sender committed to. Plaintext is written only after
 * both the digest and the AEAD tag have been checked.
 *
 * Call with a null `buf` to learn the plaintext size.
 *
 * # Safety
 *
 * `decoder` and `key` must be live handles; `session_id` and `nonce` must
 * point to 16 and 24 readable bytes; `buf` must be null or point to `len`
 * writable bytes.
 */
DhowStatus dhow_decoder_finish(const DhowDecoder *decoder,
                               const DhowKey *key,
                               const uint8_t *session_id,
                               const uint8_t *salt,
                               const uint8_t *nonce,
                               uint8_t *buf,
                               uintptr_t len,
                               uintptr_t *written);

/**
 * Serializes the decoder's progress as a resume file.
 *
 * `journal_bytes` is the length of the caller's journal at this moment. The
 * caller owns the journal, so only it knows how long the file is; the decoder
 * knows only which frames were in it.
 *
 * Call with a null `buf` to learn the required size.
 *
 * # Safety
 *
 * `decoder` must be a live handle; `buf` must be null or point to `len`
 * writable bytes; `written` must be null or writable.
 */
DhowStatus dhow_decoder_resume_state(const DhowDecoder *decoder,
                                     uint64_t journal_bytes,
                                     uint8_t *buf,
                                     uintptr_t len,
                                     uintptr_t *written);

/**
 * Reads a resume file's header without needing a decoder.
 *
 * A restarting receiver needs the session ID and journal length *before* it
 * can build a decoder and replay: the length says how much of the journal is
 * covered, and the session ID says whether this state belongs to the transfer
 * in hand at all.
 *
 * Returns [`DhowStatus::ResumeRejected`] if the file is malformed or fails its
 * integrity checks. Any output pointer may be null if the caller does not
 * want that field.
 *
 * # Safety
 *
 * `state` must point to `state_len` readable bytes. `session_id_out` must be
 * null or point to 16 writable bytes; the other outputs must be null or
 * writable.
 */
DhowStatus dhow_resume_state_read(const uint8_t *state,
                                  uintptr_t state_len,
                                  uint8_t *session_id_out,
                                  uint64_t *journal_bytes_out,
                                  uint32_t *block_count_out);

/**
 * Checks a resume file against what this decoder holds after a replay.
 *
 * Returns [`DhowStatus::ResumeRejected`] when the state is malformed, belongs
 * to another session, or describes a journal other than the one replayed.
 *
 * This is not what keeps forged symbols out: every replayed frame is
 * authenticated against the session key on the way in, and a resume file
 * carries no key. What it catches is a stale, truncated, reordered, or
 * swapped pair of files being mistaken for progress that was really made.
 *
 * # Safety
 *
 * `decoder` must be a live handle and `state` must point to `state_len`
 * readable bytes.
 */
DhowStatus dhow_decoder_resume_verify(const DhowDecoder *decoder,
                                      const uint8_t *state,
                                      uintptr_t state_len);

/**
 * Releases a decoder handle. Passing null is a no-op.
 *
 * # Safety
 *
 * `decoder` must be null or a handle from this library that has not been
 * freed.
 */
void dhow_decoder_free(DhowDecoder *decoder);

/**
 * Computes the BLAKE3 digest of a byte range.
 *
 * Exposed so a caller does not need its own BLAKE3. The digests that decide
 * whether a transfer verified are computed by this library; a second
 * implementation on the calling side would be a second thing to be wrong, and
 * the two would disagree silently rather than loudly.
 *
 * `data` must be non-null even for a zero-length input, matching every other
 * buffer argument in this API; a caller hashing nothing passes any valid
 * pointer with a length of zero.
 *
 * # Safety
 *
 * `data` must point to `len` readable bytes, and `out` must point to 32
 * writable bytes.
 */
DhowStatus dhow_blake3(const uint8_t *data, uintptr_t len, uint8_t *out);

/**
 * Creates a streaming BLAKE3 hasher.
 *
 * The one-shot [`dhow_blake3`] needs the whole input in memory at once. A
 * caller hashing a file it is streaming somewhere else - which is what
 * packing a dataset does - would otherwise have to buffer the file only to
 * hash it, turning a bounded working set into one that grows with the largest
 * file in the dataset.
 *
 * Returns null on failure.
 */
DhowHasher *dhow_hasher_new(void);

/**
 * Adds bytes to a hasher.
 *
 * # Safety
 *
 * `hasher` must be a live handle and `data` must point to `len` readable
 * bytes.
 */
DhowStatus dhow_hasher_update(DhowHasher *hasher, const uint8_t *data, uintptr_t len);

/**
 * Writes the digest of everything added so far.
 *
 * The hasher is left usable, so a caller may keep adding and finish again.
 *
 * # Safety
 *
 * `hasher` must be a live handle and `out` must point to 32 writable bytes.
 */
DhowStatus dhow_hasher_finish(const DhowHasher *hasher, uint8_t *out);

/**
 * Releases a hasher handle. Passing null is a no-op.
 *
 * # Safety
 *
 * `hasher` must be null or a handle from this library that has not been
 * freed.
 */
void dhow_hasher_free(DhowHasher *hasher);

/**
 * Reports how many bytes one QR code holds at `version` and `ecc`.
 *
 * `ecc` is the ASCII letter `L`, `M`, `Q`, or `H`. Returns a negative status
 * on invalid input.
 */
int dhow_qr_capacity(uint8_t version, char ecc);

/**
 * Reports the largest codec symbol size that still fits one QR code.
 *
 * Returns 0 when the version is too small to hold even a frame header, or a
 * negative status on invalid input. A caller uses this to choose a symbol
 * size the optical layer can actually carry, rather than picking one and
 * discovering at render time that frames do not fit.
 */
int dhow_qr_max_symbol_size(uint8_t version, char ecc);

/**
 * Encodes one frame as a QR code and writes its module grid.
 *
 * The grid is one byte per module, row-major, 1 for dark. `size` receives the
 * number of modules per side, so the caller knows the grid is `size * size`
 * bytes.
 *
 * Call with a null `buf` to learn the required size. Pass `version` 0 to let
 * the encoder choose the smallest version that fits.
 *
 * # Safety
 *
 * `frame` must point to `frame_len` readable bytes; `buf` must be null or
 * point to `len` writable bytes; `size` and `written` must be null or
 * writable.
 */
DhowStatus dhow_qr_encode_frame(const uint8_t *frame,
                                uintptr_t frame_len,
                                uint8_t version,
                                char ecc,
                                uint8_t *buf,
                                uintptr_t len,
                                uint32_t *size,
                                uintptr_t *written);

/**
 * Generates a new identity keypair.
 *
 * Returns null on failure; the secret half never crosses the boundary.
 */
DhowIdentity *dhow_identity_generate(void);

/**
 * Loads an identity keypair from a key file.
 *
 * Fails if the file is missing, malformed, holds an operator key rather than
 * an identity, or is readable by anyone but its owner.
 *
 * # Safety
 *
 * `path` must be a NUL-terminated C string.
 */
DhowIdentity *dhow_identity_load(const char *path);

/**
 * Writes an identity keypair to a key file with owner-only permissions.
 *
 * # Safety
 *
 * `identity` must be a live handle and `path` a NUL-terminated C string.
 */
DhowStatus dhow_identity_save(const DhowIdentity *identity, const char *path);

/**
 * Returns the public half of an identity as a new handle.
 *
 * Returns null on failure.
 *
 * # Safety
 *
 * `identity` must be a live handle.
 */
DhowPublicIdentity *dhow_identity_public(const DhowIdentity *identity);

/**
 * Releases an identity handle. Passing null is a no-op.
 *
 * # Safety
 *
 * `identity` must be null or a handle from this library that has not been
 * freed.
 */
void dhow_identity_free(DhowIdentity *identity);

/**
 * Loads a public identity from a 32-byte public key file.
 *
 * # Safety
 *
 * `path` must be a NUL-terminated C string.
 */
DhowPublicIdentity *dhow_public_load(const char *path);

/**
 * Writes a public identity to a file.
 *
 * # Safety
 *
 * `public` must be a live handle and `path` a NUL-terminated C string.
 */
DhowStatus dhow_public_save(const DhowPublicIdentity *public_, const char *path);

/**
 * Writes the 32-byte encoding of a public identity.
 *
 * # Safety
 *
 * `public` must be a live handle and `out` must point to 32 writable bytes.
 */
DhowStatus dhow_public_bytes(const DhowPublicIdentity *public_, uint8_t *out);

/**
 * Writes the short fingerprint of a public identity, without its NUL.
 *
 * Follows the two-call convention: pass a null buffer to learn the length.
 * The fingerprint is for an operator comparing two machines by eye and must
 * not be used as an identifier in any security check.
 *
 * # Safety
 *
 * `public` must be a live handle; `buf` must be null or point to `len`
 * writable bytes; `written` must be null or writable.
 */
DhowStatus dhow_public_fingerprint(const DhowPublicIdentity *public_,
                                   uint8_t *buf,
                                   uintptr_t len,
                                   uintptr_t *written);

/**
 * Releases a public identity handle. Passing null is a no-op.
 *
 * # Safety
 *
 * `public` must be null or a handle from this library that has not been freed.
 */
void dhow_public_free(DhowPublicIdentity *public_);

/**
 * Builds and signs a manifest.
 *
 * The payload digest and payload size come from `params`, so the manifest
 * cannot describe a payload the session does not. The total size is summed
 * from the entries rather than taken from the caller: a sender has no reason
 * to declare a total that disagrees with its own inventory, and the receiver's
 * policy check rejects one that does.
 *
 * Returns null on failure.
 *
 * # Safety
 *
 * `identity` must be a live handle; `session_id`, `salt`, and `nonce` must
 * point to 16, 32, and 24 readable bytes; `entries` must point to `count`
 * readable entries with NUL-terminated names.
 */
DhowManifest *dhow_manifest_build(const DhowIdentity *identity,
                                  const uint8_t *session_id,
                                  const uint8_t *salt,
                                  const uint8_t *nonce,
                                  DhowSessionParams params,
                                  const DhowFileEntry *entries,
                                  uintptr_t count);

/**
 * Verifies a manifest against a public identity.
 *
 * `session_id` may be null, meaning the caller has nothing to bind the
 * manifest to yet - the ordinary case for a receiver meeting a transfer for
 * the first time, where the manifest is what tells it which session this is.
 * When it is non-null, a correctly signed manifest from a different transfer
 * between the same operators is rejected.
 *
 * Returns null on failure, with the reason available from
 * `dhow_last_error_message`.
 *
 * # Safety
 *
 * `public` must be a live handle; `bytes` must point to `len` readable bytes;
 * `session_id` must be null or point to 16 readable bytes.
 */
DhowManifest *dhow_manifest_verify(const DhowPublicIdentity *public_,
                                   const uint8_t *bytes,
                                   uintptr_t len,
                                   const uint8_t *session_id);

/**
 * Writes a manifest's wire bytes, following the two-call size convention.
 *
 * # Safety
 *
 * `manifest` must be a live handle; `buf` must be null or point to `len`
 * writable bytes; `written` must be null or writable.
 */
DhowStatus dhow_manifest_bytes(const DhowManifest *manifest,
                               uint8_t *buf,
                               uintptr_t len,
                               uintptr_t *written);

/**
 * Writes a manifest's 16-byte session identifier.
 *
 * # Safety
 *
 * `manifest` must be a live handle and `out` must point to 16 writable bytes.
 */
DhowStatus dhow_manifest_session_id(const DhowManifest *manifest, uint8_t *out);

/**
 * Writes a manifest's 32-byte HKDF salt.
 *
 * # Safety
 *
 * `manifest` must be a live handle and `out` must point to 32 writable bytes.
 */
DhowStatus dhow_manifest_salt(const DhowManifest *manifest, uint8_t *out);

/**
 * Writes a manifest's 24-byte AEAD nonce.
 *
 * # Safety
 *
 * `manifest` must be a live handle and `out` must point to 24 writable bytes.
 */
DhowStatus dhow_manifest_nonce(const DhowManifest *manifest, uint8_t *out);

/**
 * Writes a manifest's session parameters.
 *
 * # Safety
 *
 * `manifest` must be a live handle and `out` must be writable.
 */
DhowStatus dhow_manifest_params(const DhowManifest *manifest, DhowSessionParams *out);

/**
 * Returns the number of file entries, or a negative status on failure.
 *
 * # Safety
 *
 * `manifest` must be a live handle.
 */
int dhow_manifest_file_count(const DhowManifest *manifest);

/**
 * Writes one entry's name, without a NUL, following the two-call convention.
 *
 * # Safety
 *
 * `manifest` must be a live handle; `buf` must be null or point to `len`
 * writable bytes; `written` must be null or writable.
 */
DhowStatus dhow_manifest_file_name(const DhowManifest *manifest,
                                   uintptr_t index,
                                   uint8_t *buf,
                                   uintptr_t len,
                                   uintptr_t *written);

/**
 * Writes one entry's size in bytes.
 *
 * # Safety
 *
 * `manifest` must be a live handle and `out` must be writable.
 */
DhowStatus dhow_manifest_file_size(const DhowManifest *manifest, uintptr_t index, uint64_t *out);

/**
 * Writes one entry's 32-byte content digest.
 *
 * # Safety
 *
 * `manifest` must be a live handle and `out` must point to 32 writable bytes.
 */
DhowStatus dhow_manifest_file_digest(const DhowManifest *manifest, uintptr_t index, uint8_t *out);

/**
 * Returns 1 if an entry is executable, 0 if not, or a negative status.
 *
 * # Safety
 *
 * `manifest` must be a live handle.
 */
int dhow_manifest_file_executable(const DhowManifest *manifest, uintptr_t index);

/**
 * Releases a manifest handle. Passing null is a no-op.
 *
 * # Safety
 *
 * `manifest` must be null or a handle from this library that has not been
 * freed.
 */
void dhow_manifest_free(DhowManifest *manifest);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* DHOW_H */
