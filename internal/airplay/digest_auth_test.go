package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestRTSPRequestAnswersDigestChallenge drives rtspRequest against a fake
// receiver that behaves like an Apple TV with "Require Password" enabled: the
// first request is refused with a Digest challenge, and only a request bearing
// a matching Authorization header succeeds.
//
// This is the end-to-end guard for the retry. A unit test of digestRetryHeader
// alone passes even when rtspRequestOnce drops the response headers on its
// error path, which makes an answerable challenge look unanswerable.
func TestRTSPRequestAnswersDigestChallenge(t *testing.T) {
	const (
		password = "s3cr3t"
		realm    = "airplay"
		nonce    = "MTc4NTE4NzY0NyAdeqAzeNIhSe0923w+y6HS"
		uri      = "rtsp://127.0.0.1/stream"
	)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type result struct {
		requests []rtspTestRequest
		err      error
	}
	done := make(chan result, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer conn.Close()
		conn = authenticatedTransportTestServer(conn)

		var seen []rtspTestRequest
		reader := bufio.NewReader(conn)

		// First request: refuse with a challenge.
		req, err := readRTSPTestRequest(reader)
		if err != nil {
			done <- result{err: err}
			return
		}
		seen = append(seen, req)
		if err := writeRTSPTestResponse(conn, 401, map[string]string{
			"WWW-Authenticate": `Digest realm="` + realm + `", nonce="` + nonce + `"`,
		}, nil); err != nil {
			done <- result{err: err}
			return
		}

		// Second request: accept only if it carries the right response.
		req, err = readRTSPTestRequest(reader)
		if err != nil {
			done <- result{err: err}
			return
		}
		seen = append(seen, req)

		want := digestResponse(DigestUsername, realm, password, nonce, "SETUP", uri)
		status := 401
		if strings.Contains(req.headers["authorization"], `response="`+want+`"`) {
			status = 200
		}
		err = writeRTSPTestResponse(conn, status, nil, []byte("ok"))
		done <- result{requests: seen, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewAirPlayClient("127.0.0.1", listener.Addr().(*net.TCPAddr).Port)
	client.SetPassword(password)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	authenticateTransportTestClient(t, client)

	body, _, err := client.rtspRequest("SETUP", uri, "text/plain", []byte("x"), nil)
	if err != nil {
		t.Fatalf("rtspRequest: expected the retry to succeed, got %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("fake receiver: %v", res.err)
	}
	if len(res.requests) != 2 {
		t.Fatalf("receiver saw %d requests, want 2 (challenge then retry)", len(res.requests))
	}
	if got := res.requests[0].headers["authorization"]; got != "" {
		t.Errorf("first request should be unauthenticated, carried Authorization: %q", got)
	}
	if got := res.requests[1].headers["authorization"]; !strings.HasPrefix(got, "Digest ") {
		t.Errorf("retry Authorization = %q, want a Digest header", got)
	}
}

// Transport tests start after successful pairing. Their fixed keys exercise
// real HAP framing; security_auth_test.go covers authenticating and pinning them.
func authenticateTransportTestClient(t *testing.T, client *AirPlayClient) {
	t.Helper()
	client.PairKeys = &PairKeys{
		ReceiverID:     "transport-test-receiver",
		ReceiverPublic: bytes.Repeat([]byte{0x41}, ed25519.PublicKeySize),
		SharedSecret:   transportTestSecret(),
	}
	client.pairingProtocol = pairingProtocolHAP
	client.encrypted = true
	client.encWriteKey = bytes.Repeat([]byte{0x42}, chacha20poly1305.KeySize)
	client.encReadKey = bytes.Repeat([]byte{0x43}, chacha20poly1305.KeySize)
	var err error
	client.encCipher, err = chacha20poly1305.New(client.encWriteKey)
	if err != nil {
		t.Fatal(err)
	}
}

func transportTestSecret() []byte { return bytes.Repeat([]byte{0x44}, 32) }

type authenticatedTransportTestConn struct {
	net.Conn
	stream *receiverHAPStream
}

func (c *authenticatedTransportTestConn) Read(data []byte) (int, error) {
	return c.stream.Read(data)
}

func (c *authenticatedTransportTestConn) Write(data []byte) (int, error) {
	return c.stream.Write(data)
}

func authenticatedTransportTestServer(conn net.Conn) net.Conn {
	stream, err := newReceiverHAPStream(conn, bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		panic(err)
	}
	return &authenticatedTransportTestConn{Conn: conn, stream: stream}
}

func authenticatedTransportTestEvents(conn net.Conn) net.Conn {
	readKey := hkdfSHA512(transportTestSecret(), []byte("Events-Salt"), []byte("Events-Read-Encryption-Key"), 32)
	writeKey := hkdfSHA512(transportTestSecret(), []byte("Events-Salt"), []byte("Events-Write-Encryption-Key"), 32)
	stream, err := newReceiverHAPStream(conn, readKey, writeKey)
	if err != nil {
		panic(err)
	}
	return &authenticatedTransportTestConn{Conn: conn, stream: stream}
}

// TestRTSPRequestWithoutPasswordDoesNotRetry checks that an unconfigured
// password leaves the 401 to surface rather than retrying blindly.
func TestRTSPRequestWithoutPasswordDoesNotRetry(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	count := make(chan int, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			count <- -1
			return
		}
		defer conn.Close()
		conn = authenticatedTransportTestServer(conn)

		reader := bufio.NewReader(conn)
		n := 0
		for {
			if _, err := readRTSPTestRequest(reader); err != nil {
				count <- n
				return
			}
			n++
			if err := writeRTSPTestResponse(conn, 401, map[string]string{
				"WWW-Authenticate": `Digest realm="airplay", nonce="abc"`,
			}, nil); err != nil {
				count <- n
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewAirPlayClient("127.0.0.1", listener.Addr().(*net.TCPAddr).Port)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	authenticateTransportTestClient(t, client)
	if _, _, err := client.rtspRequest("SETUP", "rtsp://127.0.0.1/stream", "text/plain", []byte("x"), nil); !errors.Is(err, ErrCredentialsRequired) {
		t.Fatalf("error = %v, want ErrCredentialsRequired", err)
	} else {
		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != 401 {
			t.Fatalf("error = %v, want wrapped HTTP 401", err)
		}
	}
	client.Close()

	if n := <-count; n != 1 {
		t.Errorf("receiver saw %d requests, want exactly 1 (no retry without a password)", n)
	}
}

// TestCachedChallengeAuthenticatesLaterRequests checks that only the first
// request on a connection pays for the retry. A mirroring session issues around
// two dozen requests, and a receiver that challenges one challenges them all, so
// the nonce is cached on first sight and reused up front from then on.
func TestCachedChallengeAuthenticatesLaterRequests(t *testing.T) {
	const (
		password = "s3cr3t"
		realm    = "airplay"
		nonce    = "cachedNonce123"
		setupURI = "rtsp://127.0.0.1/stream"
	)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type result struct {
		requests []rtspTestRequest
		err      error
	}
	done := make(chan result, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer conn.Close()
		conn = authenticatedTransportTestServer(conn)

		var seen []rtspTestRequest
		reader := bufio.NewReader(conn)
		for {
			req, err := readRTSPTestRequest(reader)
			if err != nil {
				done <- result{requests: seen, err: nil}
				return
			}
			seen = append(seen, req)

			// A password-protected receiver challenges every unauthenticated
			// request, whatever the method.
			want := digestResponse(DigestUsername, realm, password, nonce, req.method, setupURI)
			if !strings.Contains(req.headers["authorization"], `response="`+want+`"`) {
				if err := writeRTSPTestResponse(conn, 401, map[string]string{
					"WWW-Authenticate": `Digest realm="` + realm + `", nonce="` + nonce + `"`,
				}, nil); err != nil {
					done <- result{requests: seen, err: err}
					return
				}
				continue
			}
			if err := writeRTSPTestResponse(conn, 200, nil, []byte("ok")); err != nil {
				done <- result{requests: seen, err: err}
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewAirPlayClient("127.0.0.1", listener.Addr().(*net.TCPAddr).Port)
	client.SetPassword(password)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// First request on the connection: challenged, then retried with credentials.
	authenticateTransportTestClient(t, client)
	if _, _, err := client.rtspRequest("SETUP", setupURI, "text/plain", []byte("x"), nil); err != nil {
		t.Fatalf("SETUP: %v", err)
	}
	// Second request: the nonce is known, so this must not be challenged again.
	body, _, err := client.rtspRequest("RECORD", setupURI, "", nil, nil)
	if err != nil {
		t.Fatalf("RECORD: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
	client.Close()

	res := <-done
	if res.err != nil {
		t.Fatalf("fake receiver: %v", res.err)
	}

	var methods []string
	for _, r := range res.requests {
		methods = append(methods, r.method)
	}
	want := []string{"SETUP", "SETUP", "RECORD"}
	if len(methods) != len(want) {
		t.Fatalf("receiver saw %v, want %v (RECORD must not be sent twice)", methods, want)
	}
	for i := range want {
		if methods[i] != want[i] {
			t.Fatalf("receiver saw %v, want %v", methods, want)
		}
	}
	if auth := res.requests[0].headers["authorization"]; auth != "" {
		t.Errorf("first SETUP carried an Authorization header %q; there was no nonce to build it from yet", auth)
	}
	if auth := res.requests[2].headers["authorization"]; !strings.HasPrefix(auth, "Digest ") {
		t.Errorf("RECORD went out unauthenticated (%q); the cached challenge should have covered it", auth)
	}
}
