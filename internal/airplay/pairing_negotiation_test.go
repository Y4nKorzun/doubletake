package airplay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const testModernPairingFeatures = FeatureSystemPairing | FeatureTransientPairing | uint64(1<<38) | uint64(1<<46)

func TestPINPairingDoesNotFallbackOnUnsupportedHAP(t *testing.T) {
	testNoRawFallbackAfterPINResponses(t, 1, func(_ int) (int, []byte) { return 500, nil }, "HTTP 500")
}

func TestRawLegacyPairingRequiresPIN(t *testing.T) {
	clientConn, serverConn := newPairingNegotiationPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()
	client := &AirPlayClient{conn: clientConn, info: &ReceiverInfo{Features: FeatureLegacyPairing}}
	if err := client.Pair(context.Background(), ""); !errors.Is(err, ErrPINRequired) {
		t.Fatalf("legacy pairing without PIN = %v, want ErrPINRequired", err)
	}
	if client.PairKeys != nil || client.encrypted {
		t.Fatal("refused raw pairing mutated authentication state")
	}
	if err := requireNoPairingFallback(bufio.NewReader(serverConn), serverConn); err != nil {
		t.Fatal(err)
	}
}

func TestPINPairingDoesNotFallbackOnTLVAuthentication(t *testing.T) {
	testNoRawFallbackAfterPINResponses(t, 1, func(_ int) (int, []byte) {
		return 200, tlv8EncodeOrdered([]tlv8Item{
			{Tag: tlvState, Value: []byte{2}},
			{Tag: tlvError, Value: []byte{2}},
		})
	}, "authentication (2)")
}

func TestPINPairingDoesNotFallbackOnTLVBackoff(t *testing.T) {
	testNoRawFallbackAfterPINResponses(t, pairSetupBackoffRetries+1, func(_ int) (int, []byte) {
		return 200, tlv8EncodeOrdered([]tlv8Item{
			{Tag: tlvState, Value: []byte{2}},
			{Tag: tlvError, Value: []byte{pairingErrorBackoff}},
			{Tag: tlvRetryDelay, Value: []byte{0}},
		})
	}, "persisted")
}

func TestPINPairingDoesNotFallbackAfterHAPVerificationStarts(t *testing.T) {
	state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
	clientConn, serverConn := newPairingNegotiationPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()
	client := &AirPlayClient{conn: clientConn, PairingID: "12345678-1234-4234-8234-123456789abc", info: &ReceiverInfo{Features: testModernPairingFeatures}}
	serverDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		for i := 0; i < 3; i++ {
			request, err := readRTSPTestRequest(reader)
			if err != nil {
				serverDone <- err
				return
			}
			if request.uri != "/pair-setup" {
				serverDone <- fmt.Errorf("setup path = %s", request.uri)
				return
			}
			response, err := state.pairSetup(request.body)
			if err == nil {
				err = writeRTSPTestResponse(serverConn, 200, nil, response)
			}
			if err != nil {
				serverDone <- err
				return
			}
		}
		request, err := readRTSPTestRequest(reader)
		if err == nil && request.uri != "/pair-verify" {
			err = fmt.Errorf("verification path = %s", request.uri)
		}
		if err == nil {
			err = writeRTSPTestResponse(serverConn, 500, nil, nil)
		}
		if err == nil {
			err = requireNoPairingFallback(reader, serverConn)
		}
		serverDone <- err
	}()
	if err := client.Pair(context.Background(), "4827"); err == nil || !strings.Contains(err.Error(), "pair-verify") {
		t.Fatalf("Pair = %v, want verification failure", err)
	}
	waitPairingTestServer(t, serverDone)
}

func testNoRawFallbackAfterPINResponses(t *testing.T, responseCount int, response func(int) (int, []byte), wantError string) {
	t.Helper()
	clientConn, serverConn := newPairingNegotiationPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()
	client := &AirPlayClient{conn: clientConn, PairingID: "12345678-1234-4234-8234-123456789abc", info: &ReceiverInfo{Features: testModernPairingFeatures}}
	serverDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		for i := 0; i < responseCount; i++ {
			request, err := readRTSPTestRequest(reader)
			if err == nil {
				err = requireAuthenticatedHAPM1(request)
			}
			if err == nil {
				status, body := response(i)
				err = writeRTSPTestResponse(serverConn, status, nil, body)
			}
			if err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- requireNoPairingFallback(reader, serverConn)
	}()
	if err := client.Pair(context.Background(), "4827"); err == nil || !strings.Contains(err.Error(), wantError) {
		t.Fatalf("Pair = %v, want %q", err, wantError)
	}
	if client.encrypted {
		t.Fatal("failed pairing enabled encryption")
	}
	waitPairingTestServer(t, serverDone)
}

func requireAuthenticatedHAPM1(request rtspTestRequest) error {
	if request.method != "POST" || request.uri != "/pair-setup" || request.headers["x-apple-hkp"] != "5" {
		return fmt.Errorf("unexpected PIN setup request: %s %s (%v)", request.method, request.uri, request.headers)
	}
	message := tlv8Decode(request.body)
	if !bytes.Equal(message[tlvState], []byte{1}) || !bytes.Equal(message[tlvMethod], []byte{0}) || len(message[tlvFlags]) != 0 {
		return fmt.Errorf("PIN setup incorrectly used transient flags: %x", request.body)
	}
	return nil
}

func requireNoPairingFallback(reader *bufio.Reader, conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return err
	}
	if request, err := readRTSPTestRequest(reader); err == nil {
		return fmt.Errorf("unexpected fallback request: %s %s", request.method, request.uri)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return err
	}
	return nil
}

func newPairingNegotiationPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return clientConn, serverConn
}
