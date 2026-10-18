package airplay

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// SavedCredentials holds the persistent pairing credentials and optional
// screencast restore state for a single device.
type SavedCredentials struct {
	PairingID       string          `json:"pairing_id"`
	Ed25519Public   []byte          `json:"ed25519_public"`
	Ed25519Seed     []byte          `json:"ed25519_seed"` // 32-byte seed (private key is derived from this)
	ReceiverID      string          `json:"receiver_id,omitempty"`
	ReceiverPublic  []byte          `json:"receiver_public,omitempty"`
	PairingProtocol PairingProtocol `json:"pairing_protocol,omitempty"`
	RestoreToken    string          `json:"restore_token,omitempty"`
}

// PairingProtocol is the pair-verify wire protocol negotiated when credentials
// were created. It must be restored before reusing the keys: HAP pair-verify
// enables encrypted control framing, while raw AirPlay pair-verify does not.
type PairingProtocol string

const (
	PairingProtocolUnknown PairingProtocol = ""
	PairingProtocolHAP     PairingProtocol = "hap"
	PairingProtocolRaw     PairingProtocol = "raw"
)

// DefaultCredentialsPath returns ~/.config/doubletake/credentials.json.
func DefaultCredentialsPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "doubletake", "credentials.json")
}

// Ed25519Keys reconstructs the key pair from saved credentials.
func (c *SavedCredentials) Ed25519Keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(c.Ed25519Seed) != ed25519.SeedSize {
		return nil, nil
	}
	priv := ed25519.NewKeyFromSeed(c.Ed25519Seed)
	return ed25519.PublicKey(c.Ed25519Public), priv
}

// HasPairingCredentials reports whether the saved entry contains a usable
// AirPlay pairing identity.
func (c *SavedCredentials) HasPairingCredentials() bool {
	return c != nil && c.PairingID != "" &&
		len(c.Ed25519Public) == ed25519.PublicKeySize &&
		len(c.Ed25519Seed) == ed25519.SeedSize
}

// RestorePairingCredentials installs a saved identity and its negotiated wire
// protocol on the client. Call this before PairVerify.
func (c *AirPlayClient) RestorePairingCredentials(saved *SavedCredentials) error {
	if saved == nil || !saved.HasPairingCredentials() {
		return fmt.Errorf("saved credentials contain no usable pairing identity")
	}
	if saved.ReceiverID == "" || len(saved.ReceiverPublic) != ed25519.PublicKeySize {
		return fmt.Errorf("saved credentials have no verified receiver identity; verify the receiver and pair again with -pair")
	}
	protocol := saved.PairingProtocol
	switch protocol {
	case PairingProtocolHAP:
		c.pairingProtocol = pairingProtocolHAP
	case PairingProtocolRaw:
		c.pairingProtocol = pairingProtocolRaw
	default:
		return fmt.Errorf("saved credentials contain unknown pairing protocol %q", protocol)
	}

	pub, priv := saved.Ed25519Keys()
	if !pub.Equal(priv.Public()) {
		return fmt.Errorf("saved pairing public and private keys do not match")
	}
	c.PairingID = saved.PairingID
	c.PairKeys = &PairKeys{
		Ed25519Public:  append(ed25519.PublicKey(nil), pub...),
		Ed25519Private: append(ed25519.PrivateKey(nil), priv...),
		ReceiverID:     saved.ReceiverID,
		ReceiverPublic: append(ed25519.PublicKey(nil), saved.ReceiverPublic...),
	}
	return nil
}

// CredentialBackend is the storage interface for pairing credentials.
type CredentialBackend interface {
	Lookup(deviceID string) (*SavedCredentials, error)
	Save(deviceID string, creds *SavedCredentials) error
}

// CredentialStore manages per-device pairing credentials using a pluggable backend.
type CredentialStore struct {
	mu      sync.Mutex
	backend CredentialBackend
}

// NewCredentialStore creates a credential store backed by a JSON file at path.
func NewCredentialStore(path string) (*CredentialStore, error) {
	fb, err := newFileBackend(path)
	if err != nil {
		return nil, err
	}
	return &CredentialStore{backend: fb}, nil
}

// NewCredentialStoreWithBackend creates a credential store with the given backend.
func NewCredentialStoreWithBackend(b CredentialBackend) *CredentialStore {
	return &CredentialStore{backend: b}
}

// Lookup returns saved credentials for a device, or nil if not found.
// Deprecated: use LookupEntry so a backend error cannot trigger new pairing.
func (cs *CredentialStore) Lookup(deviceID string) *SavedCredentials {
	creds, _ := cs.LookupEntry(deviceID)
	return creds
}

// LookupEntry distinguishes an unpaired receiver from an unavailable or corrupt
// credential backend. Connection decisions must not discard its error.
func (cs *CredentialStore) LookupEntry(deviceID string) (*SavedCredentials, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	creds, err := cs.backend.Lookup(deviceID)
	if err != nil {
		return nil, fmt.Errorf("look up saved receiver identity: %w", err)
	}
	if creds != nil && !creds.HasPairingCredentials() &&
		(creds.PairingID != "" || len(creds.Ed25519Public) != 0 || len(creds.Ed25519Seed) != 0 ||
			creds.ReceiverID != "" || len(creds.ReceiverPublic) != 0 || creds.PairingProtocol != PairingProtocolUnknown) {
		return nil, fmt.Errorf("saved receiver identity is incomplete; verify the receiver before explicitly pairing again")
	}
	return creds, nil
}

// Len returns the number of stored credential entries.
// Only supported by the file backend; returns 0 for other backends.
func (cs *CredentialStore) Len() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if fb, ok := cs.backend.(*fileBackend); ok {
		return len(fb.devices)
	}
	return 0
}

// Save stores credentials for a device.
func (cs *CredentialStore) Save(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	return cs.savePairing(deviceID, pairingID, pub, priv, PairingProtocolUnknown, "", nil)
}

// SavePairing stores credentials together with the protocol which actually
// completed. Use SaveAuthenticatedPairing to preserve receiver verification.
func (cs *CredentialStore) SavePairing(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, protocol PairingProtocol) error {
	if protocol != PairingProtocolHAP && protocol != PairingProtocolRaw {
		return fmt.Errorf("cannot save unknown pairing protocol %q", protocol)
	}
	return cs.savePairing(deviceID, pairingID, pub, priv, protocol, "", nil)
}

// SaveAuthenticatedPairing retains the receiver identity verified during pairing.
func (cs *CredentialStore) SaveAuthenticatedPairing(deviceID, pairingID string, keys *PairKeys, protocol PairingProtocol) error {
	if !keys.hasReceiverIdentity() {
		return fmt.Errorf("cannot save pairing without a verified receiver identity")
	}
	if protocol != PairingProtocolHAP && protocol != PairingProtocolRaw {
		return fmt.Errorf("cannot save unknown pairing protocol %q", protocol)
	}
	return cs.savePairing(deviceID, pairingID, keys.Ed25519Public, keys.Ed25519Private, protocol, keys.ReceiverID, keys.ReceiverPublic)
}

func (cs *CredentialStore) savePairing(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, protocol PairingProtocol, receiverID string, receiverPublic ed25519.PublicKey) error {
	if deviceID == "" || pairingID == "" || len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize || !pub.Equal(priv.Public()) {
		return fmt.Errorf("cannot save invalid pairing identity")
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()

	creds, err := cs.backend.Lookup(deviceID)
	if err != nil {
		return err
	}
	if creds == nil {
		creds = &SavedCredentials{}
	}
	creds.PairingID = pairingID
	creds.Ed25519Public = append([]byte(nil), pub...)
	creds.Ed25519Seed = append([]byte(nil), priv.Seed()...)
	creds.ReceiverID = receiverID
	creds.ReceiverPublic = append([]byte(nil), receiverPublic...)
	if protocol != PairingProtocolUnknown {
		creds.PairingProtocol = protocol
	}
	return cs.backend.Save(deviceID, creds)
}

// SaveRestoreToken stores a Wayland screencast restore token for a device.
func (cs *CredentialStore) SaveRestoreToken(deviceID, restoreToken string) error {
	if restoreToken == "" {
		return nil
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	creds, err := cs.backend.Lookup(deviceID)
	if err != nil {
		return err
	}
	if creds == nil {
		creds = &SavedCredentials{}
	}
	creds.RestoreToken = restoreToken
	return cs.backend.Save(deviceID, creds)
}

// fileBackend stores credentials as a JSON file on disk.
type fileBackend struct {
	path    string
	devices map[string]*SavedCredentials
}

func newFileBackend(path string) (*fileBackend, error) {
	fb := &fileBackend{
		path:    path,
		devices: make(map[string]*SavedCredentials),
	}
	if err := validateCredentialDirectory(filepath.Dir(path)); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	metadata, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fb, nil
		}
		return nil, fmt.Errorf("read credential store: %w", err)
	}
	if !metadata.Mode().IsRegular() || metadata.Mode().Perm()&0077 != 0 || !credentialOwnedByUser(metadata) {
		return nil, fmt.Errorf("credential store must be a private, user-owned regular file (mode 0600)")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential store: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(metadata, opened) {
		return nil, fmt.Errorf("credential store changed while opening")
	}
	const maxCredentialBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read credential store: %w", err)
	}
	if len(data) > maxCredentialBytes {
		return nil, fmt.Errorf("credential store exceeds size limit")
	}
	if err := json.Unmarshal(data, &fb.devices); err != nil {
		return nil, fmt.Errorf("unmarshal credential store: %w", err)
	}
	if fb.devices == nil {
		return nil, fmt.Errorf("credential store must be an object")
	}
	return fb, nil
}

func validateCredentialDirectory(path string) error {
	metadata, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !metadata.IsDir() || metadata.Mode().Perm()&0022 != 0 || !credentialOwnedByUser(metadata) {
		return fmt.Errorf("credential directory must be owned by the current user and not writable by other users")
	}
	return nil
}

func credentialOwnedByUser(metadata os.FileInfo) bool {
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

func (fb *fileBackend) Lookup(deviceID string) (*SavedCredentials, error) {
	creds, exists := fb.devices[deviceID]
	if exists && creds == nil {
		return nil, fmt.Errorf("saved receiver entry is null")
	}
	return creds, nil
}

func (fb *fileBackend) Save(deviceID string, creds *SavedCredentials) error {
	fb.devices[deviceID] = creds
	return fb.persist()
}

func (fb *fileBackend) persist() error {
	dir := filepath.Dir(fb.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create credential dir: %w", err)
	}
	if err := validateCredentialDirectory(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fb.devices, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credential store: %w", err)
	}
	file, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return fmt.Errorf("create credential file: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write credential store: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync credential store: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close credential store: %w", err)
	}
	if err := os.Rename(file.Name(), fb.path); err != nil {
		return fmt.Errorf("replace credential store: %w", err)
	}
	return nil
}
