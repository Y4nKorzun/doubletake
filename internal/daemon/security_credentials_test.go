package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"doubletake/internal/airplay"
	"howett.net/plist"
)

type securityUnavailableCredentialBackend struct{}

func (securityUnavailableCredentialBackend) Lookup(string) (*airplay.SavedCredentials, error) {
	return nil, errors.New("keyring unavailable")
}

func (securityUnavailableCredentialBackend) Save(string, *airplay.SavedCredentials) error {
	return errors.New("unexpected attempt to replace unavailable credentials")
}

func TestSecurityBackendFailureDoesNotStartNewPairing(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	body, err := plist.Marshal(map[string]any{
		"name": "receiver", "deviceID": "device", "features": uint64(airplay.FeatureSystemPairing),
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		request, err := readPINFlowRequest(conn, reader)
		if err == nil && request.path != "/info" {
			err = fmt.Errorf("first request was %q", request.path)
		}
		if err == nil {
			err = writePINFlowResponse(conn, request.headers["cseq"], 200, "application/x-apple-binary-plist", body)
		}
		if err != nil {
			done <- err
			return
		}
		if next, err := readPINFlowRequest(conn, reader); err == nil {
			done <- fmt.Errorf("backend failure was followed by %s %s", next.method, next.path)
			return
		}
		done <- nil
	}()
	d, err := New(Config{CredFile: filepath.Join(t.TempDir(), "credentials.json"), NoAudio: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Shutdown)
	d.credStore = airplay.NewCredentialStoreWithBackend(securityUnavailableCredentialBackend{})
	addr := listener.Addr().(*net.TCPAddr)
	if response := d.handleConnect(Request{Cmd: "connect", Target: addr.IP.String(), Port: addr.Port}); !response.OK {
		t.Fatalf("connect rejected: %+v", response)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("connection did not close after credential failure")
	}
	status := d.handleStatus()
	if status.NeedsCredential || !strings.Contains(status.Error, "keyring unavailable") {
		t.Fatalf("backend failure did not fail closed: %+v", status)
	}
}
