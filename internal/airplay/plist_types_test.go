package airplay

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"

	"howett.net/plist"
)

func decodeInfo(t *testing.T, info map[string]interface{}) ReceiverInfo {
	t.Helper()
	body, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ReceiverInfo
	if _, err := plist.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return got
}

func TestReceiverInfoAcceptsEitherEncoding(t *testing.T) {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i)
	}

	strict := map[string]interface{}{
		"pk":                       pk,
		"keepAliveSendStatsAsBody": true,
		"displays": []interface{}{map[string]interface{}{
			"widthPixels": uint64(1920), "heightPixels": uint64(1080),
		}},
	}
	loose := map[string]interface{}{
		"pk":                       hex.EncodeToString(pk),
		"keepAliveSendStatsAsBody": uint64(1),
		"displays": []interface{}{map[string]interface{}{
			"widthPixels": 1920.0, "heightPixels": 1080.0,
		}},
	}

	for name, info := range map[string]map[string]interface{}{
		"strict": strict,
		"loose":  loose,
	} {
		t.Run(name, func(t *testing.T) {
			got := decodeInfo(t, info)
			if hex.EncodeToString(got.PK) != hex.EncodeToString(pk) {
				t.Errorf("PK = %x, want %x", got.PK, pk)
			}
			if !got.KeepAliveBody {
				t.Error("KeepAliveBody = false, want true")
			}
			if w, h := got.DisplaySize(); w != 1920 || h != 1080 {
				t.Errorf("DisplaySize() = %dx%d, want 1920x1080", w, h)
			}
		})
	}
}

func TestReceiverInfoRejectsUndecodablePK(t *testing.T) {
	body, err := plist.Marshal(map[string]interface{}{"pk": "not hex"}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ReceiverInfo
	if _, err := plist.Unmarshal(body, &got); err == nil {
		t.Fatal("expected an error for a pk that is neither data nor hex")
	}
}

func TestReceiverDisplayDimensionsRejectInvalidNumbers(t *testing.T) {
	for _, test := range []struct {
		name  string
		value interface{}
	}{
		{name: "NaN", value: math.NaN()},
		{name: "positive infinity", value: math.Inf(1)},
		{name: "negative infinity", value: math.Inf(-1)},
		{name: "negative integer", value: int64(-1)},
		{name: "integer overflow", value: uint64(math.MaxUint64)},
		{name: "real overflow", value: math.MaxFloat64},
		{name: "fractional pixels", value: 1920.5},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := test.value
			real, isReal := value.(float64)
			if isReal && math.IsNaN(real) {
				// The upstream serializer cannot deduplicate NaN map keys. Build a
				// finite real object and replace its bits with a valid binary NaN.
				value = 12345.6789012345
			}
			body, err := plist.Marshal(map[string]interface{}{
				"displays": []interface{}{map[string]interface{}{
					"widthPixels": value, "heightPixels": uint64(1080),
				}},
			}, plist.BinaryFormat)
			if err != nil {
				t.Fatal(err)
			}
			if isReal && math.IsNaN(real) {
				encodedReal := make([]byte, 9)
				encodedReal[0] = 0x23
				binary.BigEndian.PutUint64(encodedReal[1:], math.Float64bits(value.(float64)))
				offset := bytes.Index(body, encodedReal)
				if offset < 0 {
					t.Fatal("finite real fixture was not encoded as a double")
				}
				binary.BigEndian.PutUint64(body[offset+1:], math.Float64bits(real))
			}
			var info ReceiverInfo
			if _, err := plist.Unmarshal(body, &info); err == nil {
				t.Fatal("receiver display accepted a nonfinite, negative, fractional or overflowing dimension")
			}
		})
	}
}

func TestReceiverInfoMaxVideoSize(t *testing.T) {
	info := decodeInfo(t, map[string]interface{}{
		"displays": []interface{}{map[string]interface{}{
			"widthPixels":     uint64(1280),
			"heightPixels":    uint64(720),
			"widthPixelsMax":  uint64(1920),
			"heightPixelsMax": uint64(1080),
		}},
	})
	if w, h := info.DisplaySize(); w != 1280 || h != 720 {
		t.Fatalf("DisplaySize() = %dx%d, want display size 1280x720", w, h)
	}
	if w, h := info.MirrorSize(); w != 1280 || h != 720 {
		t.Fatalf("MirrorSize() = %dx%d, want nominal canvas 1280x720", w, h)
	}
	if w, h := info.MaxVideoSize(); w != 1920 || h != 1080 {
		t.Fatalf("MaxVideoSize() = %dx%d, want decoder limit 1920x1080", w, h)
	}

	info.Displays[0].WidthPixelsMax = 0
	info.Displays[0].HeightPixelsMax = 0
	if w, h := info.MaxVideoSize(); w != 1280 || h != 720 {
		t.Fatalf("MaxVideoSize() fallback = %dx%d, want display size 1280x720", w, h)
	}
}

func TestReceiverInfoMaxVideoSizeWithoutDisplayMetadata(t *testing.T) {
	tests := []struct {
		name  string
		info  ReceiverInfo
		wantW int
		wantH int
	}{
		{
			name:  "macOS 26.6",
			info:  ReceiverInfo{Features: 0x38174fde4a7fcfd5},
			wantW: 1280,
			wantH: 720,
		},
		{
			name:  "AppleTV14",
			info:  ReceiverInfo{Features: 0x3c177fde4a7fdfd5},
			wantW: 1280,
			wantH: 720,
		},
		{
			name: "Roku explicit display",
			info: ReceiverInfo{
				Features: 0x38bcf46007f8ad0,
				Displays: []DisplayInfo{{
					WidthPixels:     1920,
					HeightPixels:    1080,
					WidthPixelsMax:  1920,
					HeightPixelsMax: 1080,
				}},
			},
			wantW: 1920,
			wantH: 1080,
		},
		{
			name:  "AppleTV3,2",
			info:  ReceiverInfo{Features: 0x1e5a7ffff7},
			wantW: 1920,
			wantH: 1080,
		},
		{
			name:  "legacy screen without 1080p default feature",
			info:  ReceiverInfo{Features: FeatureScreen},
			wantW: 1280,
			wantH: 720,
		},
		{
			name: "receiver without screen mirroring",
			info: ReceiverInfo{Features: FeatureAudio},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if w, h := tt.info.MirrorSize(); w != tt.wantW || h != tt.wantH {
				t.Fatalf("MirrorSize() = %dx%d, want %dx%d", w, h, tt.wantW, tt.wantH)
			}
			if w, h := tt.info.MaxVideoSize(); w != tt.wantW || h != tt.wantH {
				t.Fatalf("MaxVideoSize() = %dx%d, want %dx%d", w, h, tt.wantW, tt.wantH)
			}
		})
	}
}
