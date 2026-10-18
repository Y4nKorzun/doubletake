package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
)

type timingSecurityPacket struct {
	data []byte
	addr net.Addr
}

type timingSecurityConn struct {
	recordingPacketConn
	incoming []timingSecurityPacket
}

func (c *timingSecurityConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	if len(c.incoming) == 0 {
		return 0, nil, io.EOF
	}
	packet := c.incoming[0]
	c.incoming = c.incoming[1:]
	return copy(dst, packet.data), packet.addr, nil
}

func TestNTPTimingResponderOnlyAnswersAuthenticatedControlPeer(t *testing.T) {
	packet := make([]byte, 32)
	packet[0], packet[1] = 0x80, 0xd2
	receiverIP := net.ParseIP("192.0.2.10")
	receiverAddr := &net.UDPAddr{IP: receiverIP, Port: 7010}
	foreignAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 7010}
	for _, test := range []struct {
		name        string
		expectedIP  net.IP
		wantReplies int
	}{
		{name: "pinned receiver", expectedIP: receiverIP, wantReplies: 1},
		{name: "missing receiver fails closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &timingSecurityConn{incoming: []timingSecurityPacket{
				{data: packet, addr: foreignAddr},
				{data: packet, addr: &net.TCPAddr{IP: receiverIP, Port: 7010}},
				{data: packet[:31], addr: receiverAddr},
				{data: packet, addr: receiverAddr},
			}}
			ntpTimingResponder(context.Background(), conn, test.expectedIP)
			if len(conn.packets) != test.wantReplies {
				t.Fatalf("sent %d replies, want %d", len(conn.packets), test.wantReplies)
			}
			if test.wantReplies != 0 {
				if conn.addrs[0] != receiverAddr || len(conn.packets[0]) != 32 || conn.packets[0][1] != 0xd3 {
					t.Fatalf("unexpected timing response: destination=%v packet=%x", conn.addrs[0], conn.packets[0])
				}
			}
		})
	}
}

func TestAudioControlWithoutReceiverFailsClosed(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7001}
	for _, stream := range []*AudioStream{{}, {ctrlAddr: &net.UDPAddr{Port: 7001}}} {
		if stream.audioControlPacketFromReceiver(peer) {
			t.Fatal("control packet accepted without a pinned receiver IP")
		}
	}
}

func TestAudioSetupRejectsMissingEncryptionMaterial(t *testing.T) {
	for _, test := range []struct {
		name string
		mode audioSecurityMode
		key  []byte
		iv   []byte
	}{
		{name: "missing AES key", mode: audioSecurityLegacyAES, iv: make([]byte, aes.BlockSize)},
		{name: "missing AES IV", mode: audioSecurityLegacyAES, key: make([]byte, aes.BlockSize)},
		{name: "short AES IV", mode: audioSecurityLegacyAES, key: make([]byte, aes.BlockSize), iv: []byte{1}},
		{name: "missing ChaCha key", mode: audioSecurityChaCha},
		{name: "unknown encryption mode", mode: audioSecurityMode(-1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Invalid encryption material must be rejected before any network work,
			// even when the session has no initialized client or media sockets.
			session := &MirrorSession{}
			if _, err := session.setupAudioStream(7000, 7001, test.key, test.iv, nil, test.mode, byte(AudioCodecALAC), 0, false, nil, nil); err == nil {
				t.Fatal("audio setup accepted missing or invalid encryption material")
			}
		})
	}
}

func TestAudioDebugLogsDoNotExposeCapturedSamplesOrIV(t *testing.T) {
	previousDebug := DebugMode()
	previousOutput := log.Writer()
	var output bytes.Buffer
	log.SetOutput(&output)
	SetDebugMode(true)
	t.Cleanup(func() {
		SetDebugMode(previousDebug)
		log.SetOutput(previousOutput)
	})

	key := bytes.Repeat([]byte{0xa7}, aes.BlockSize)
	iv := bytes.Repeat([]byte{0x6b}, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	sample := []byte("captured private audio samples must never enter logs")
	stream := &AudioStream{cipher: block, aesIV: iv}
	stream.buildAudioPacketLocked(sample, 1234, 1, audioDataPayloadType, nil)
	for _, secret := range []string{
		string(sample[:16]),
		fmt.Sprintf("%02x", sample[:16]),
		fmt.Sprintf("%02x", key),
		fmt.Sprintf("%02x", iv),
	} {
		if bytes.Contains(output.Bytes(), []byte(secret)) {
			t.Fatal("debug output exposed captured samples or encryption material")
		}
	}
}

var _ net.PacketConn = (*timingSecurityConn)(nil)
