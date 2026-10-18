package airplay

import (
	"context"
	"strings"
	"testing"
)

func TestReceiverVideoCanvasUsesMaximumOnlyForCapabilityGatedHEVC(t *testing.T) {
	info := &ReceiverInfo{
		Features: uint64(1) << featureScreenMultiCodec,
		Displays: []DisplayInfo{{
			WidthPixels: 1280, HeightPixels: 720,
			WidthPixelsMax: 3840, HeightPixelsMax: 2160,
		}},
	}
	if width, height, err := info.videoCanvas(VideoCodecH264); err != nil || width != 1280 || height != 720 {
		t.Fatalf("H.264 canvas = %dx%d err=%v, want nominal 1280x720", width, height, err)
	}
	if width, height, err := info.videoCanvas(VideoCodecHEVC); err != nil || width != 3840 || height != 2160 {
		t.Fatalf("HEVC canvas = %dx%d err=%v, want maximum 3840x2160", width, height, err)
	}
	info.Features &^= uint64(1) << featureScreenMultiCodec
	if _, _, err := info.videoCanvas(VideoCodecHEVC); err == nil {
		t.Fatal("HEVC canvas accepted without feature 42")
	}
}

func TestAutomaticVideoSelectionUsesNominalH264(t *testing.T) {
	tests := []struct {
		name string
		info *ReceiverInfo
	}{
		{name: "multi-codec high resolution", info: &ReceiverInfo{
			Features: uint64(1) << featureScreenMultiCodec,
			Displays: []DisplayInfo{{WidthPixels: 1280, HeightPixels: 720, WidthPixelsMax: 3840, HeightPixelsMax: 2160}},
		}},
		{name: "legacy receiver", info: &ReceiverInfo{
			Displays: []DisplayInfo{{WidthPixels: 1280, HeightPixels: 720}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection, err := test.info.selectVideo(VideoCodecAuto, true)
			if err != nil {
				t.Fatal(err)
			}
			if selection.codec != VideoCodecH264 || selection.width != 1280 || selection.height != 720 {
				t.Fatalf("selection = %s %dx%d, want H.264 1280x720", selection.codec, selection.width, selection.height)
			}
			if !strings.Contains(selection.reason, "compatibility") {
				t.Fatalf("reason = %q, want compatibility reason", selection.reason)
			}
		})
	}
}

func TestExplicitHEVCSelectionCapsMaximumPreservingAspect(t *testing.T) {
	info := &ReceiverInfo{
		Features: uint64(1) << featureScreenMultiCodec,
		Displays: []DisplayInfo{{
			WidthPixels: 1920, HeightPixels: 1080,
			WidthPixelsMax: 7680, HeightPixelsMax: 2160,
		}},
	}
	forced, err := info.selectVideo(VideoCodecHEVC, false)
	if err != nil {
		t.Fatal(err)
	}
	if forced.width != 3840 || forced.height != 1080 {
		t.Fatalf("forced HEVC canvas = %dx%d, want capped 3840x1080", forced.width, forced.height)
	}
}

func TestEveryVideoCodecBoundsReceiverCanvasBeforeEncoding(t *testing.T) {
	maximumInt := int(^uint(0) >> 1)
	for _, test := range []struct {
		name          string
		width, height int
		wantW, wantH  int
		wantError     bool
	}{
		{name: "8K receiver", width: 7680, height: 4320, wantW: 3840, wantH: 2160},
		{name: "wide receiver", width: 7680, height: 2160, wantW: 3840, wantH: 1080},
		{name: "maximum integers cannot overflow", width: maximumInt, height: maximumInt, wantW: 2160, wantH: 2160},
		{name: "degenerate height after scaling", width: maximumInt, height: 1080, wantError: true},
		{name: "degenerate width", width: 1, height: 1080, wantError: true},
	} {
		for _, codec := range []VideoCodec{VideoCodecAuto, VideoCodecH264, VideoCodecHEVC} {
			t.Run(test.name+"/"+string(codec), func(t *testing.T) {
				info := &ReceiverInfo{
					Features: uint64(1) << featureScreenMultiCodec,
					Displays: []DisplayInfo{{
						WidthPixels: plistNumber(test.width), HeightPixels: plistNumber(test.height),
						WidthPixelsMax: plistNumber(test.width), HeightPixelsMax: plistNumber(test.height),
					}},
				}
				selection, err := info.selectVideo(codec, false)
				if test.wantError {
					if err == nil {
						t.Fatalf("pathological receiver canvas was accepted: %#v", selection)
					}
					return
				}
				if err != nil || selection.width != test.wantW || selection.height != test.wantH {
					t.Fatalf("selected canvas = %dx%d err=%v, want %dx%d", selection.width, selection.height, err, test.wantW, test.wantH)
				}
			})
		}
	}
}

func TestMissingReceiverCanvasUsesBoundedBaseline(t *testing.T) {
	selection, err := (&ReceiverInfo{}).selectVideo(VideoCodecAuto, false)
	if err != nil || selection.width != 1280 || selection.height != 720 {
		t.Fatalf("missing receiver canvas selected %dx%d err=%v, want bounded 1280x720", selection.width, selection.height, err)
	}
}

func TestExplicitVideoCodecOverridesAutomaticPolicy(t *testing.T) {
	info := &ReceiverInfo{
		Features: uint64(1) << featureScreenMultiCodec,
		Displays: []DisplayInfo{{
			WidthPixels: 1280, HeightPixels: 720,
			WidthPixelsMax: 3840, HeightPixelsMax: 2160,
		}},
	}
	h264, err := info.selectVideo(VideoCodecH264, true)
	if err != nil {
		t.Fatal(err)
	}
	if h264.codec != VideoCodecH264 || h264.width != 1280 || h264.height != 720 {
		t.Fatalf("explicit H.264 = %s %dx%d", h264.codec, h264.width, h264.height)
	}

	hevc, err := info.selectVideo(VideoCodecHEVC, false)
	if err != nil {
		t.Fatal(err)
	}
	if hevc.codec != VideoCodecHEVC || hevc.width != 3840 || hevc.height != 2160 {
		t.Fatalf("explicit HEVC = %s %dx%d", hevc.codec, hevc.width, hevc.height)
	}
}

func TestValidateVideoCodecAcceptsAuto(t *testing.T) {
	for _, codec := range []string{"", "auto", "h264", "hevc"} {
		if err := ValidateVideoCodec(codec); err != nil {
			t.Errorf("ValidateVideoCodec(%q): %v", codec, err)
		}
	}
	if err := ValidateVideoCodec("vp9"); err == nil || !strings.Contains(err.Error(), "auto, h264, or hevc") {
		t.Fatalf("ValidateVideoCodec(vp9) error = %v", err)
	}
}

func TestLegacyMirrorPreparationAPIRejectsAutomaticCodec(t *testing.T) {
	client := &AirPlayClient{}
	if _, err := client.SetupMirror(context.Background(), StreamConfig{VideoCodec: VideoCodecAuto}); err == nil || !strings.Contains(err.Error(), "VideoCodecPreparation") {
		t.Fatalf("SetupMirror(auto) error = %v", err)
	}
	if _, err := client.SetupMirrorWithVideoPreparation(context.Background(), StreamConfig{VideoCodec: VideoCodecAuto}, func(int, int) error { return nil }); err == nil || !strings.Contains(err.Error(), "VideoCodecPreparation") {
		t.Fatalf("legacy preparation(auto) error = %v", err)
	}
}
