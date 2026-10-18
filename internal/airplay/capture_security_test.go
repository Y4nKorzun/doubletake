package airplay

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestSecurityPortalOnlyDoesNotRequireDirectDisplaySocket(t *testing.T) {
	t.Setenv("XDG_SESSION_TYPE", "wayland")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")
	kind, err := captureKind(CaptureConfig{PortalOnly: true})
	if err != nil || kind != capturePreparationWayland {
		t.Fatalf("portal-only selection = %v, %v", kind, err)
	}
	if _, err := captureKind(CaptureConfig{PortalOnly: true, X11WindowID: 1}); err == nil {
		t.Fatal("portal-only capture accepted an X11 override")
	}
	t.Setenv("XDG_SESSION_TYPE", "x11")
	if _, err := captureKind(CaptureConfig{PortalOnly: true}); err == nil {
		t.Fatal("portal-only capture accepted an X11 session")
	}
}

func TestSecurityPortalOnlyCannotRestorePersistentGrant(t *testing.T) {
	options := map[string]dbus.Variant{}
	setPortalPersistence(options, 4, "previously-authorized-screen", false)
	if options["persist_mode"].Value() != uint32(0) {
		t.Fatal("ephemeral portal request enabled persistence")
	}
	if _, ok := options["restore_token"]; ok {
		t.Fatal("ephemeral portal request reused a screen grant")
	}
}
