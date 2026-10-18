package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSecurityDigestRequiresAuthenticatedEncryptedReceiver(t *testing.T) {
	for _, variant := range []string{"unverified", "pinned but plaintext", "encrypted but unpinned", "raw protocol", "authenticated HAP"} {
		t.Run(variant, func(t *testing.T) {
			client := &AirPlayClient{authPassword: "4827", authChallenge: &digestChallenge{Realm: "airplay", Nonce: "chosen-by-attacker"}}
			if variant != "unverified" && variant != "encrypted but unpinned" {
				client.PairKeys = &PairKeys{ReceiverID: "receiver", ReceiverPublic: bytes.Repeat([]byte{1}, ed25519.PublicKeySize)}
			}
			client.encrypted = variant != "unverified" && variant != "pinned but plaintext"
			client.pairingProtocol = pairingProtocolHAP
			if variant == "raw protocol" {
				client.pairingProtocol = pairingProtocolRaw
			}
			want := variant == "authenticated HAP"
			header, ok := client.preemptiveAuthHeader("GET", "/info")
			if ok != want || (!want && header != "") {
				t.Fatalf("preemptive authentication = (%q, %t), want permitted=%t", header, ok, want)
			}
			client.authChallenge = nil
			header, ok, err := client.digestRetryHeader("GET", "/info", map[string]string{
				"www-authenticate": `Digest realm="airplay", nonce="chosen-by-attacker"`,
			}, &HTTPStatusError{StatusCode: 401})
			if ok != want || (!want && header != "") || err == nil {
				t.Fatalf("Digest retry = (%q, %t, %v), want permitted=%t", header, ok, err, want)
			}
			if !want && client.authChallenge != nil {
				t.Fatal("unverified challenge was cached for future authorization")
			}
		})
	}
}

func TestSecurityNoPINVerifierSentToUnverifiedReceiver(t *testing.T) {
	clientConn, receiverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); receiverConn.Close() })
	client := NewAirPlayClient("127.0.0.1", 7000)
	client.conn = clientConn
	client.SetPassword("4827") // Defense even if a caller confuses PIN and password.
	done := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(receiverConn)
		req, err := readRTSPTestRequest(reader)
		if err != nil {
			done <- err
			return
		}
		if req.headers["authorization"] != "" {
			done <- fmt.Errorf("initial request disclosed an Authorization header")
			return
		}
		if err := writeRTSPTestResponse(receiverConn, 401, map[string]string{
			"WWW-Authenticate": `Digest realm="airplay", nonce="chosen-by-attacker"`,
		}, nil); err != nil {
			done <- err
			return
		}
		if _, err := readRTSPTestRequest(reader); err == nil {
			done <- fmt.Errorf("client retried an unauthenticated challenge")
			return
		}
		done <- nil
	}()
	if _, err := client.GetInfo(); err == nil || !strings.Contains(err.Error(), "refusing Digest") {
		t.Fatalf("GetInfo error = %v, want unauthenticated Digest refusal", err)
	}
	client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("receiver did not terminate")
	}
}

func TestSecurityAuthenticatedHAPPairingPinsReceiver(t *testing.T) {
	state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
	conn, done, closePair := runReceiverPairingServer(t, state, 3, 2)
	defer closePair()
	client := NewAirPlayClient("127.0.0.1", 7000)
	client.conn = conn
	if err := client.Pair(context.Background(), "4827"); err != nil {
		t.Fatalf("PIN pairing: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !client.authenticatedControl() || client.PairKeys.ReceiverID != state.identifier || !bytes.Equal(client.PairKeys.ReceiverPublic, state.publicKey) {
		t.Fatal("pairing did not authenticate and pin the expected receiver")
	}
	if client.authPassword != "" {
		t.Fatal("pairing PIN was installed as a Digest password")
	}
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthenticatedPairing("device", client.PairingID, client.PairKeys, client.PairingProtocol()); err != nil {
		t.Fatal(err)
	}
	saved, err := store.LookupEntry("device")
	if err != nil {
		t.Fatal(err)
	}
	restored := NewAirPlayClient("127.0.0.1", 7000)
	if err := restored.RestorePairingCredentials(saved); err != nil {
		t.Fatal(err)
	}
	if restored.PairKeys.ReceiverID != state.identifier || !bytes.Equal(restored.PairKeys.ReceiverPublic, state.publicKey) {
		t.Fatal("saving/restoring credentials lost the receiver identity")
	}
	receiver := newReceiverPairingTestState(t, "4827", state.controllers)
	restoredConn, restoredDone, closeRestored := runReceiverPairingServer(t, receiver, 0, 2)
	defer closeRestored()
	restored.conn = restoredConn
	if err := restored.PairVerify(context.Background()); err != nil {
		t.Fatalf("verify saved identity: %v", err)
	}
	if err := <-restoredDone; err != nil {
		t.Fatal(err)
	}
	if !restored.authenticatedControl() {
		t.Fatal("saved identity did not establish authenticated encryption")
	}
}

func TestSecurityReconnectDoesNotInheritAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client := NewAirPlayClient("127.0.0.1", listener.Addr().(*net.TCPAddr).Port)
	client.PairKeys = &PairKeys{
		ReceiverID: "receiver", ReceiverPublic: bytes.Repeat([]byte{1}, ed25519.PublicKeySize),
		SharedSecret: []byte("old shared secret"), WriteKey: []byte("old write key"), ReadKey: []byte("old read key"),
	}
	client.encrypted = true
	client.pairingProtocol = pairingProtocolHAP
	client.authChallenge = &digestChallenge{Realm: "old", Nonce: "old"}
	client.fpKey, client.streamKey = []byte("old video key"), []byte("old stream key")
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.authenticatedControl() || client.authChallenge != nil || client.PairKeys.SharedSecret != nil || client.fpKey != nil || client.streamKey != nil {
		t.Fatal("new TCP connection inherited authentication or media keys")
	}
	if !client.PairKeys.hasReceiverIdentity() {
		t.Fatal("reconnect lost the pinned long-term identity")
	}
}

func TestSecurityPairSetupRejectsMissingProofAndForgedIdentity(t *testing.T) {
	for _, stage := range []byte{4, 6} {
		t.Run(fmt.Sprintf("M%d", stage), func(t *testing.T) {
			state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
			client := newReceiverPairingTestClient(t)
			clientConn, receiverConn := net.Pipe()
			t.Cleanup(func() { clientConn.Close(); receiverConn.Close() })
			client.conn = clientConn
			done := make(chan error, 1)
			go func() {
				defer receiverConn.Close()
				reader := bufio.NewReader(receiverConn)
				for i := byte(2); i <= stage; i += 2 {
					req, err := readRTSPTestRequest(reader)
					if err != nil {
						done <- err
						return
					}
					var sharedKey []byte
					if state.setup != nil {
						sharedKey = append([]byte(nil), state.setup.sharedKey...)
					}
					response, err := state.pairSetup(req.body)
					if err != nil {
						done <- err
						return
					}
					if i == stage {
						if stage == 4 {
							response = tlv8EncodeOrdered([]tlv8Item{{Tag: tlvState, Value: []byte{4}}})
						} else {
							key := hkdfSHA512(sharedKey, []byte("Pair-Setup-Encrypt-Salt"), []byte("Pair-Setup-Encrypt-Info"), 32)
							aead, _ := chacha20poly1305.New(key)
							identity := tlv8EncodeOrdered([]tlv8Item{
								{Tag: tlvIdentifier, Value: []byte(state.identifier)},
								{Tag: tlvPublicKey, Value: state.publicKey},
								{Tag: tlvSignature, Value: make([]byte, ed25519.SignatureSize)},
							})
							response = tlv8EncodeOrdered([]tlv8Item{
								{Tag: tlvState, Value: []byte{6}},
								{Tag: tlvEncryptedData, Value: aead.Seal(nil, receiverPairingNonce("PS-Msg06"), identity, nil)},
							})
						}
					}
					if err := writeRTSPTestResponse(receiverConn, 200, nil, response); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			err := client.pairSetup(context.Background(), "4827")
			if err == nil || client.PairKeys.hasReceiverIdentity() || client.encrypted {
				t.Fatalf("forged M%d accepted or left receiver trusted: %v", stage, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSecurityPairVerifyRejectsImpersonatingReceiver(t *testing.T) {
	for _, variant := range []string{"different identifier", "different signing key", "invalid signature"} {
		t.Run(variant, func(t *testing.T) {
			state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
			client := newReceiverPairingTestClient(t)
			client.PairKeys.ReceiverID = state.identifier
			client.PairKeys.ReceiverPublic = append(ed25519.PublicKey(nil), state.publicKey...)
			if variant == "different identifier" {
				state.identifier = "impostor"
			}
			if variant == "different signing key" {
				state.privateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
			}
			clientConn, receiverConn := net.Pipe()
			t.Cleanup(func() { clientConn.Close(); receiverConn.Close() })
			client.conn = clientConn
			done := make(chan error, 1)
			go func() {
				defer receiverConn.Close()
				req, err := readRTSPTestRequest(bufio.NewReader(receiverConn))
				if err != nil {
					done <- err
					return
				}
				response, err := state.pairVerify(req.body)
				if err == nil && variant == "invalid signature" {
					aead, _ := chacha20poly1305.New(state.verify.verifyKey)
					identity := tlv8EncodeOrdered([]tlv8Item{
						{Tag: tlvIdentifier, Value: []byte(state.identifier)},
						{Tag: tlvSignature, Value: make([]byte, ed25519.SignatureSize)},
					})
					response = tlv8EncodeOrdered([]tlv8Item{
						{Tag: tlvState, Value: []byte{2}},
						{Tag: tlvPublicKey, Value: state.verify.serverPublic},
						{Tag: tlvEncryptedData, Value: aead.Seal(nil, receiverPairingNonce("PV-Msg02"), identity, nil)},
					})
				}
				if err == nil {
					err = writeRTSPTestResponse(receiverConn, 200, nil, response)
				}
				done <- err
			}()
			if err := client.PairVerify(context.Background()); err == nil || client.encrypted {
				t.Fatalf("receiver impersonation accepted: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type securityFailingCredentialBackend struct{ err error }

func (b securityFailingCredentialBackend) Lookup(string) (*SavedCredentials, error) {
	return nil, b.err
}
func (b securityFailingCredentialBackend) Save(string, *SavedCredentials) error { return b.err }

func TestSecurityCredentialLookupPreservesBackendFailure(t *testing.T) {
	failure := errors.New("keyring unavailable")
	store := NewCredentialStoreWithBackend(securityFailingCredentialBackend{err: failure})
	if _, err := store.LookupEntry("receiver"); !errors.Is(err, failure) {
		t.Fatalf("lookup error = %v, want backend failure", err)
	}
}

func TestSecurityIncompleteCredentialEntryDoesNotBecomeUnpaired(t *testing.T) {
	for _, data := range []string{`{"receiver":null}`, `{"receiver":{"pairing_id":"old-trusted-pair"}}`} {
		path := filepath.Join(t.TempDir(), "credentials.json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		store, err := NewCredentialStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.LookupEntry("receiver"); err == nil {
			t.Fatal("incomplete saved pairing was treated as an unpaired receiver")
		}
	}
}

func TestSecurityCredentialFileRejectsUnsafeStorage(t *testing.T) {
	for _, variant := range []string{"public file", "symlink", "writable directory", "null map"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "credentials.json")
			data := []byte(`{}`)
			if variant == "null map" {
				data = []byte(`null`)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "public file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(dir, "link.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "writable directory":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewCredentialStore(path); err == nil {
				t.Fatal("unsafe credential storage accepted")
			}
		})
	}
}
