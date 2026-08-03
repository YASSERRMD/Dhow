package ffi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

var (
	manifestSession = [16]byte{0x5A}
	manifestSalt    = [32]byte{0x11}
	manifestNonce   = [24]byte{0x22}
)

func manifestParams() SessionParams {
	return SessionParams{
		PayloadSize:           4096,
		BlockCount:            2,
		SymbolSize:            256,
		SourceSymbolsPerBlock: 8,
		TotalSymbolsPerBlock:  12,
		PayloadDigest:         [32]byte{0x7E},
	}
}

func sampleEntries() []FileEntry {
	return []FileEntry{
		{Name: "docs/readme.md", Size: 100, Digest: [32]byte{0x01}, Executable: false},
		{Name: "run.sh", Size: 12, Digest: [32]byte{0x02}, Executable: true},
		{Name: "nested/deep/blob.bin", Size: 65536, Digest: [32]byte{0x03}},
	}
}

// signedManifest builds a manifest and returns its wire bytes with the
// identity that signed it.
func signedManifest(t *testing.T, entries []FileEntry) (*Identity, []byte) {
	t.Helper()
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	t.Cleanup(identity.Close)

	m, err := BuildManifest(identity, manifestSession, manifestSalt, manifestNonce, manifestParams(), entries)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	defer m.Close()

	raw, err := m.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return identity, raw
}

func publicOf(t *testing.T, identity *Identity) *PublicIdentity {
	t.Helper()
	pub, err := identity.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	t.Cleanup(pub.Close)
	return pub
}

func TestManifestRoundTripsItsInventory(t *testing.T) {
	want := sampleEntries()
	identity, raw := signedManifest(t, want)

	m, err := VerifyManifest(publicOf(t, identity), raw, nil)
	if err != nil {
		t.Fatalf("a manifest we just signed did not verify: %v", err)
	}
	defer m.Close()

	if got, err := m.SessionID(); err != nil || got != manifestSession {
		t.Errorf("SessionID() = %x, %v; want %x", got, err, manifestSession)
	}
	if got, err := m.Salt(); err != nil || got != manifestSalt {
		t.Errorf("Salt() = %x, %v; want %x", got, err, manifestSalt)
	}
	if got, err := m.Nonce(); err != nil || got != manifestNonce {
		t.Errorf("Nonce() = %x, %v; want %x", got, err, manifestNonce)
	}
	if got, err := m.Params(); err != nil || got != manifestParams() {
		t.Errorf("Params() = %+v, %v; want %+v", got, err, manifestParams())
	}

	got, err := m.Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Files() returned %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestManifestWithNoFiles(t *testing.T) {
	identity, raw := signedManifest(t, nil)

	m, err := VerifyManifest(publicOf(t, identity), raw, nil)
	if err != nil {
		t.Fatalf("an empty manifest did not verify: %v", err)
	}
	defer m.Close()

	files, err := m.Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("Files() returned %d entries for an empty dataset", len(files))
	}
}

func TestManifestFromAnotherIdentityIsRejected(t *testing.T) {
	_, raw := signedManifest(t, sampleEntries())

	stranger, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	defer stranger.Close()

	if m, err := VerifyManifest(publicOf(t, stranger), raw, nil); err == nil {
		m.Close()
		t.Fatal("a manifest verified against an identity that did not sign it")
	}
}

func TestManifestTamperingIsCaughtAtEveryByte(t *testing.T) {
	identity, good := signedManifest(t, sampleEntries())
	pub := publicOf(t, identity)

	for i := range good {
		altered := bytes.Clone(good)
		altered[i]++
		if m, err := VerifyManifest(pub, altered, nil); err == nil {
			m.Close()
			t.Fatalf("a manifest with byte %d altered still verified", i)
		}
	}
}

func TestManifestSessionBinding(t *testing.T) {
	identity, raw := signedManifest(t, sampleEntries())
	pub := publicOf(t, identity)

	m, err := VerifyManifest(pub, raw, &manifestSession)
	if err != nil {
		t.Fatalf("the manifest's own session was rejected: %v", err)
	}
	m.Close()

	other := [16]byte{0x99}
	if m, err := VerifyManifest(pub, raw, &other); err == nil {
		m.Close()
		t.Fatal("a manifest from another session was accepted")
	}
}

func TestManifestRejectsATraversalName(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	defer identity.Close()

	for _, name := range []string{"../../etc/passwd", "/etc/passwd", "a/../../b", "a\\b"} {
		entries := []FileEntry{{Name: name, Size: 1}}
		if m, err := BuildManifest(identity, manifestSession, manifestSalt, manifestNonce, manifestParams(), entries); err == nil {
			m.Close()
			t.Errorf("signed a manifest naming %q", name)
		}
	}
}

func TestIdentityFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "sender.key")
	public := filepath.Join(dir, "sender.pub")

	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	defer identity.Close()

	if err := identity.Save(secret); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(secret)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("identity key written with mode %04o; it must not be readable by others", perm)
	}

	pub := publicOf(t, identity)
	if err := pub.Save(public); err != nil {
		t.Fatalf("Save public: %v", err)
	}

	// The whole point of the files is that the pair survives a restart: sign
	// with the reloaded secret, verify with the reloaded public half.
	reloaded, err := LoadIdentity(secret)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	defer reloaded.Close()

	m, err := BuildManifest(reloaded, manifestSession, manifestSalt, manifestNonce, manifestParams(), sampleEntries())
	if err != nil {
		t.Fatalf("BuildManifest with the reloaded identity: %v", err)
	}
	defer m.Close()
	raw, err := m.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	reloadedPub, err := LoadPublicIdentity(public)
	if err != nil {
		t.Fatalf("LoadPublicIdentity: %v", err)
	}
	defer reloadedPub.Close()

	verified, err := VerifyManifest(reloadedPub, raw, nil)
	if err != nil {
		t.Fatalf("a reloaded key pair could not verify its own signature: %v", err)
	}
	verified.Close()
}

func TestOperatorKeyDoesNotLoadAsAnIdentity(t *testing.T) {
	// Confusing the two would mean signing with a key both operators hold,
	// which proves nothing about who produced the transfer.
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer key.Close()
	if err := key.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if id, err := LoadIdentity(path); err == nil {
		id.Close()
		t.Fatal("an operator key loaded as a signing identity")
	}

	// And the reverse.
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	defer identity.Close()
	idPath := filepath.Join(dir, "sender.key")
	if err := identity.Save(idPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if k, err := LoadKey(idPath); err == nil {
		k.Close()
		t.Fatal("an identity key loaded as an operator key")
	}
}

func TestFingerprintIsStableAndShort(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	defer identity.Close()

	a := publicOf(t, identity)
	b := publicOf(t, identity)

	fa, err := a.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	fb, err := b.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if fa != fb {
		t.Errorf("the same identity produced two fingerprints: %q and %q", fa, fb)
	}
	if len(fa) != 23 {
		t.Errorf("fingerprint %q is %d characters; want 23", fa, len(fa))
	}
}

func TestClosedHandlesReportRatherThanCrash(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	pub := publicOf(t, identity)
	identity.Close()
	// Closing twice must be safe: cleanup paths should not need a guard.
	identity.Close()

	if _, err := identity.Public(); err == nil {
		t.Error("Public() on a closed identity returned no error")
	}
	if err := identity.Save("/dev/null"); err == nil {
		t.Error("Save() on a closed identity returned no error")
	}
	if _, err := BuildManifest(identity, manifestSession, manifestSalt, manifestNonce, manifestParams(), nil); err == nil {
		t.Error("BuildManifest with a closed identity returned no error")
	}

	pub.Close()
	pub.Close()
	if _, err := pub.Bytes(); err == nil {
		t.Error("Bytes() on a closed public identity returned no error")
	}
	if _, err := VerifyManifest(pub, []byte{1, 2, 3}, nil); err == nil {
		t.Error("VerifyManifest with a closed public identity returned no error")
	}

	var m *Manifest
	m.Close()
	if _, err := m.Files(); err == nil {
		t.Error("Files() on a nil manifest returned no error")
	}
}
