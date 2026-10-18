package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"doubletake/internal/airplay"
	"doubletake/internal/daemon"
	"golang.org/x/sys/unix"
)

func parseXID(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 0, 64) // accepts decimal or 0xhex
}

// parsePortRange parses a "min-max" string into inclusive port bounds.
// An empty string returns (0, 0, nil) meaning "let the OS pick".
func parsePortRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected MIN-MAX, got %q", s)
	}
	lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("min: %w", err)
	}
	hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("max: %w", err)
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("range %d-%d out of bounds (1-65535, min<=max)", lo, hi)
	}
	if hi-lo+1 < 3 {
		return 0, 0, fmt.Errorf("range %d-%d too small; need 3 consecutive UDP ports", lo, hi)
	}
	return lo, hi, nil
}

func main() {
	target := flag.String("target", "", "Apple TV IP address or hostname (skip discovery)")
	port := flag.Int("port", 7000, "AirPlay port")
	code := flag.String("code", "", "SRP pairing PIN shown on the receiver; prefer the interactive prompt or $DOUBLETAKE_CODE")
	password := flag.String("password", "", "Separate receiver playback password, sent only after identity verification; prefer the interactive prompt or $DOUBLETAKE_PASSWORD")
	credFile := flag.String("creds", airplay.DefaultCredentialsPath(), "Path to saved pairing credentials")
	credBackend := flag.String("cred-backend", "file", "Credential storage backend: file or keyring (system keyring via Secret Service)")
	forcePair := flag.Bool("pair", false, "Force new pairing even if credentials exist")
	fps := flag.Int("fps", 30, "Frames per second")
	bitrate := flag.Int("bitrate", 0, "Video bitrate in kbps (0 = auto, default tunes for resolution/FPS)")
	targetLatencyMs := flag.Int("target-latency-ms", 0, "Joint audio/video playout latency override in milliseconds (0 = automatic connection profile)")
	hwaccel := flag.String("hwaccel", "auto", "Encoder: auto, nvenc, vaapi, openh264, none (x264/x265)")
	videoCodec := flag.String("video-codec", "auto", "Screen codec: auto, h264, or hevc (auto uses H.264 for receiver compatibility)")
	testMode := flag.Bool("test", false, "Use synthetic video (videotestsrc) instead of screen capture for debugging")
	noEncrypt := flag.Bool("no-encrypt", false, "Rejected by this fork: media encryption is required")
	directKey := flag.Bool("direct-key", false, "Use shk/shiv directly without SHA-512 derivation")
	noAudio := flag.Bool("no-audio", false, "Disable audio streaming")
	portRange := flag.String("port-range", "", "Local UDP port range for receiver timing/audio (e.g. \"60000-60010\"); empty = OS ephemeral. Needs at least 3 ports.")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	daemonize := flag.Bool("daemonize", false, "Run as background daemon with Unix socket control interface")
	socketPath := flag.String("socket", daemon.DefaultSocketPath(), "Unix socket path for daemon control interface")
	x11WindowID := flag.String("x11-window-id", "", "X11 window id to capture, decimal or 0xhex")
	x11WindowName := flag.String("x11-window-name", "", "X11 window name to capture; prefer -x11-window-id")
	noCursor := flag.Bool("no-cursor", false, "Don't show the mouse cursor in the captured video")
	portalOnly := flag.Bool("portal-only", false, "Require an ephemeral desktop-portal screen grant without direct display access")
	flag.Parse()
	if err := airplay.ValidateHWAccel(*hwaccel); err != nil {
		log.Fatalf("invalid -hwaccel: %v", err)
	}
	if err := airplay.ValidateVideoCodec(*videoCodec); err != nil {
		log.Fatalf("invalid -video-codec: %v", err)
	}
	portMin, portMax, err := parsePortRange(*portRange)
	if err != nil {
		log.Fatalf("invalid -port-range: %v", err)
	}
	// The environment wins over the flag: it keeps the code out of shell history
	// and out of `ps`, where a command line is readable by other users.
	credential := *code
	if env := os.Getenv("DOUBLETAKE_CODE"); env != "" {
		credential = env
	}
	playbackPassword := *password
	if env := os.Getenv("DOUBLETAKE_PASSWORD"); env != "" {
		playbackPassword = env
	}

	airplay.SetTargetLatency(time.Duration(*targetLatencyMs) * time.Millisecond)

	airplay.SetDebugMode(*debug)

	if *daemonize {
		runDaemon(daemon.Config{
			SocketPath:  *socketPath,
			CredFile:    *credFile,
			CredBackend: *credBackend,
			FPS:         *fps,
			Bitrate:     *bitrate,
			PortMin:     portMin,
			PortMax:     portMax,
			HWAccel:     *hwaccel,
			VideoCodec:  airplay.VideoCodec(*videoCodec),
			Debug:       *debug,
			TestMode:    *testMode,
			NoEncrypt:   *noEncrypt,
			DirectKey:   *directKey,
			NoAudio:     *noAudio,
			ShowCursor:  !*noCursor,
			Code:        credential,
			Password:    playbackPassword,
			PortalOnly:  *portalOnly,
		})
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	xid, err := parseXID(*x11WindowID)
	if err != nil {
		log.Fatalf("invalid -x11-window-id: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
		// Give goroutines a moment to clean up, then force exit
		go func() {
			time.Sleep(3 * time.Second)
			log.Println("forced exit (timeout)")
			os.Exit(1)
		}()
		// Also force exit on second signal
		<-sigCh
		log.Println("forced exit")
		os.Exit(1)
	}()

	var addr string
	var advertisement *airplay.AirPlayDevice
	if *target != "" {
		addr = *target
	} else {
		device, err := selectDevice(ctx)
		if err != nil {
			log.Fatalf("discovery failed: %v", err)
		}
		addr = device.IP
		*port = device.Port
		advertisement = device
		fmt.Printf("selected: %q (%s:%d)\n", device.Name, device.IP, device.Port)
	}

	newClient := func() *airplay.AirPlayClient {
		if advertisement != nil {
			device := *advertisement
			device.IP = addr
			device.Port = *port
			return airplay.NewAirPlayClientForDevice(device)
		}
		return airplay.NewAirPlayClient(addr, *port)
	}
	client := newClient()
	client.SetPassword(playbackPassword)
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	info, err := client.GetInfo()
	if err != nil {
		log.Fatalf("get info failed: %v", err)
	}
	log.Printf("connected to: %q (model: %q, initialVolume: %.1f)", info.Name, info.Model, info.InitialVolume)

	// Only an explicit -pair may replace an existing receiver identity.
	needFullPair := *forcePair

	credStore, err := newCredentialStore(*credBackend, *credFile)
	if err != nil {
		log.Fatalf("failed to load credentials: %v", err)
	}

	var savedCreds *airplay.SavedCredentials
	if !needFullPair {
		savedCreds, err = credStore.LookupEntry(info.DeviceID)
		if err != nil {
			log.Fatalf("cannot verify saved receiver identity: %v", err)
		}
	}

	savePairingCredentials := func() {
		if client.PairKeys == nil {
			return
		}
		if err := credStore.SaveAuthenticatedPairing(info.DeviceID, client.PairingID, client.PairKeys,
			client.PairingProtocol()); err != nil {
			log.Fatalf("failed to save verified receiver identity: %v", err)
		} else {
			log.Printf("credentials saved (%s)", *credBackend)
		}
	}
	pairWithCredential := func(value string, expectPIN bool) {
		if value == "" {
			value = credentialOrPrompt("", client, expectPIN)
		}
		if passwordRequiresPairing(info) {
			playbackPassword = value
		}
		if err := client.Pair(ctx, value); err != nil {
			log.Fatalf("pairing failed: %v", err)
		}
		savePairingCredentials()
	}
	if savedCreds != nil && savedCreds.HasPairingCredentials() {
		// Use saved credentials — pair-verify
		log.Printf("using saved credentials (%s)", *credBackend)
		verifyErr := restoreSavedPairing(client, savedCreds)
		if verifyErr == nil {
			verifyErr = client.PairVerify(ctx)
		}
		if verifyErr != nil {
			log.Fatalf("receiver verification failed: %v; verify the receiver before explicitly pairing again with -pair", verifyErr)
		}
	} else {
		if passwordRequiresPairing(info) {
			value := playbackPassword
			if value == "" {
				value = readCredential(bufio.NewReader(os.Stdin), "Enter the receiver's configured SRP pairing password: ")
			}
			pairWithCredential(value, false)
		} else {
			pairWithCredential(credential, true)
		}
	}
	log.Println("pairing complete")
	if info.RequiresPassword() && playbackPassword == "" {
		playbackPassword = readCredential(bufio.NewReader(os.Stdin), "Enter the receiver's configured playback password: ")
		if playbackPassword == "" {
			log.Fatal("playback password cannot be empty")
		}
	}
	client.SetPassword(playbackPassword)

	// FairPlay setup — establishes fp-setup state and ekey/eiv used for the
	// final encrypted mirror stream. Pair-verify and FairPlay are both needed
	// for compatibility with the normal modern flow.
	if client.FpEkey == nil {
		if err := client.FairPlaySetup(ctx); err != nil {
			if !errors.Is(err, airplay.ErrFairPlayUnsupported) {
				log.Fatalf("FairPlay setup failed: %v", err)
			}
			log.Printf("FairPlay SAP unsupported (%v); continuing with pair-verify DataStream setup", err)
		} else {
			log.Println("FairPlay setup complete")
		}
	}

	streamCfg := airplay.StreamConfig{
		FPS:        *fps,
		Bitrate:    *bitrate,
		VideoCodec: airplay.VideoCodec(*videoCodec),
		NoEncrypt:  *noEncrypt,
		DirectKey:  *directKey,
		NoAudio:    *noAudio,
		PortMin:    portMin,
		PortMax:    portMax,
	}
	// Complete the potentially interactive Wayland portal request before SETUP,
	// but delay encoder startup until control SETUP returns session-time display
	// information. Some current receivers omit displays before that session
	// exists; committing the pipeline earlier silently selects the 720p fallback.
	captureCfg := airplay.CaptureConfig{
		FPS:           *fps,
		Bitrate:       *bitrate,
		HWAccel:       *hwaccel,
		VideoCodec:    airplay.VideoCodec(*videoCodec),
		X11WindowID:   xid,
		X11WindowName: *x11WindowName,
		ShowCursor:    !*noCursor,
		PortalOnly:    *portalOnly,
	}
	if *testMode {
		if *noAudio {
			log.Println("using synthetic video (videotestsrc) for debugging")
		} else {
			log.Println("using synthetic video (videotestsrc) and audio test tone for debugging")
		}
	}
	prepareCapture := func(cfg airplay.CaptureConfig) (*airplay.CapturePreparation, error) {
		if *testMode {
			return airplay.PrepareTestCapture(ctx, cfg)
		}
		restoreToken := ""
		creds, err := credStore.LookupEntry(info.DeviceID)
		if err != nil {
			return nil, err
		}
		if creds != nil {
			restoreToken = creds.RestoreToken
		}
		cfg.RestoreToken = restoreToken
		cfg.SaveRestoreToken = func(token string) error {
			return credStore.SaveRestoreToken(info.DeviceID, token)
		}
		return airplay.PrepareCapture(ctx, cfg)
	}
	capturePreparation, err := prepareCapture(captureCfg)
	if err != nil {
		log.Fatalf("prepare screen capture: %v", err)
	}
	streamCfg.AutomaticHEVCAvailable = capturePreparation.AutomaticHEVCAvailable()
	streamCfg.MeasuredVideoLatency = capturePreparation.MeasuredVideoLatency()

	var capture *airplay.ScreenCapture
	var broadcast *airplay.BroadcastCapture
	var broadcastDone chan error
	startedWidth, startedHeight := -1, -1
	startedCodec := airplay.VideoCodec("")
	var liveVideoLead time.Duration
	prepareH264Fallback := func(cause error) error {
		fallbackCfg := captureCfg
		fallbackCfg.VideoCodec = airplay.VideoCodecH264
		replacement, fallbackErr := prepareCapture(fallbackCfg)
		if fallbackErr != nil {
			return fmt.Errorf("%v; prepare H.264 fallback: %w", cause, fallbackErr)
		}
		capturePreparation.Close()
		capturePreparation = replacement
		liveVideoLead = 0
		return fmt.Errorf("%w: %v", airplay.ErrAutomaticVideoCodecUnavailable, cause)
	}
	prepareVideo := func(width, height int, codec airplay.VideoCodec) (airplay.VideoPreparationResult, error) {
		if capture != nil {
			if codec == startedCodec {
				if width != startedWidth || height != startedHeight {
					log.Printf("receiver updated the %s canvas to %dx%d after capture started; keeping %dx%d for this session", codec, width, height, startedWidth, startedHeight)
				}
				return airplay.VideoPreparationResult{MinimumVideoLead: liveVideoLead}, nil
			}
			return airplay.VideoPreparationResult{}, fmt.Errorf("receiver changed video from %s %dx%d to %s %dx%d during setup", startedCodec, startedWidth, startedHeight, codec, width, height)
		}
		startedCapture, startErr := capturePreparation.StartWithCodec(width, height, codec)
		if startErr != nil {
			if captureCfg.VideoCodec == airplay.VideoCodecAuto && codec == airplay.VideoCodecHEVC {
				return airplay.VideoPreparationResult{}, prepareH264Fallback(startErr)
			}
			return airplay.VideoPreparationResult{}, startErr
		}
		if codec == airplay.VideoCodecHEVC && !airplay.HasExplicitTargetLatency() {
			liveVideoLead, startErr = airplay.MeasureVideoCaptureLatency(ctx, startedCapture, *fps)
			if startErr != nil {
				startedCapture.Stop()
				measurementErr := fmt.Errorf("measure production HEVC timing: %w", startErr)
				if captureCfg.VideoCodec == airplay.VideoCodecAuto {
					return airplay.VideoPreparationResult{}, prepareH264Fallback(measurementErr)
				}
				return airplay.VideoPreparationResult{}, measurementErr
			}
			log.Printf("[CAPTURE] production HEVC timing requires at least %v video lead", liveVideoLead)
		}
		activeBroadcast := airplay.NewBroadcastCaptureWithFrameRate(startedCapture, *fps)
		done := make(chan error, 1)
		capture = startedCapture
		broadcast = activeBroadcast
		broadcastDone = done
		startedWidth, startedHeight = width, height
		startedCodec = codec
		go func(active *airplay.BroadcastCapture, result chan<- error) {
			result <- active.Run()
		}(activeBroadcast, done)
		log.Printf("screen capture started at %dx%d using %s", width, height, codec)
		return airplay.VideoPreparationResult{MinimumVideoLead: liveVideoLead}, nil
	}
	defer func() {
		capturePreparation.Close()
		if capture != nil {
			capture.Stop()
			<-broadcastDone
		}
	}()

	session, err := client.SetupMirrorWithCalibratedVideoPreparation(ctx, streamCfg, prepareVideo)
	if errors.Is(err, airplay.ErrCredentialsRequired) {
		// Some legacy receivers do not advertise their configured password in
		// /info. They reveal it only by challenging the first media SETUP. Keep
		// the completed pairing/FairPlay state and running capture, configure the
		// cached Digest challenge, and retry this setup exactly once.
		playbackPassword = readCredential(bufio.NewReader(os.Stdin), "Enter the receiver's configured playback password: ")
		if playbackPassword == "" {
			log.Fatal("playback password cannot be empty")
		}
		client.SetPassword(playbackPassword)
		if startedCodec != "" {
			// A late Digest challenge may expose richer authenticated display
			// metadata on the retry. The running encoder is single-use, so pin
			// the already safe concrete codec for the remainder of this session.
			streamCfg.VideoCodec = startedCodec
		}
		session, err = client.SetupMirrorWithCalibratedVideoPreparation(ctx, streamCfg, prepareVideo)
	}
	if err != nil {
		log.Fatalf("mirror setup failed: %v", err)
	}
	if capture == nil || broadcast == nil {
		log.Fatal("mirror setup completed without preparing video capture")
	}
	defer session.Close()
	log.Printf("mirror session ready (data port: %d)", session.DataPort)

	go func() {
		<-ctx.Done()
		capture.Stop()
		session.Close()
	}()

	// Start audio capture and streaming unless disabled.
	if !*noAudio && session.HasAudio() {
		audioCapture, err := airplay.StartAudioCapture(ctx, *testMode, session.AudioCodec())
		if err != nil {
			log.Printf("warning: audio capture failed: %v (continuing without audio)", err)
		} else {
			defer audioCapture.Stop()
			go func() {
				if err := session.StreamAudio(ctx, audioCapture, session.AudioStream()); err != nil && ctx.Err() == nil {
					log.Printf("audio streaming error: %v", err)
				}
			}()
			log.Println("audio capture started")
		}
	} else if !*noAudio {
		log.Println("audio disabled (receiver did not provide audio ports)")
	}

	// Keep the capture pipeline draining until the receiver is ready to consume
	// video. Holding its first access unit during setup can exhaust the portal
	// buffer pool. StreamFrames waits for the next parameter sets and keyframe.
	videoSink, err := broadcast.AddBackpressuredSink()
	if err != nil {
		log.Fatalf("attach video stream: %v", err)
	}
	defer videoSink.Close()
	if err := session.StreamFrames(ctx, videoSink.AsCapture(), 0*time.Second); err != nil && ctx.Err() == nil {
		log.Printf("streaming error: %v", err)
		return
	}
	log.Println("stream ended")
}

// credentialOrPrompt returns a supplied credential or makes one pairing-display
// request and prompts once. expectPIN is true only when the receiver advertised
// an on-screen PIN (or the user explicitly requested fresh pairing). A successful
// /pair-pin-start response alone cannot distinguish a PIN from a fixed password,
// so an unadvertised fallback keeps its prompt deliberately generic.
func credentialOrPrompt(value string, client *airplay.AirPlayClient, expectPIN bool) string {
	if value != "" {
		return value
	}

	reader := bufio.NewReader(os.Stdin)
	displayErr := client.StartPINDisplay()
	if displayErr != nil {
		if expectPIN {
			log.Fatalf("receiver did not start authenticated PIN pairing: %v", displayErr)
		}
		log.Printf("warning: failed to trigger PIN display: %v", displayErr)
	}
	credential := readCredential(reader, pairingCredentialPrompt(expectPIN, displayErr))
	if credential == "" {
		log.Fatal("pairing credential cannot be empty")
	}
	return credential
}

func pairingCredentialPrompt(expectPIN bool, displayErr error) string {
	if expectPIN && displayErr == nil {
		return "Enter the PIN shown on the receiver: "
	}
	return "Enter the receiver's configured password or pairing PIN: "
}

func passwordRequiresPairing(info *airplay.ReceiverInfo) bool {
	// A failed transient exchange can put a legacy password pairer into an error
	// state, so receivers advertising that pairing generation start with SRP.
	// Modern receivers retain the password only for Digest, even when their
	// status flags also advertise on-screen PIN pairing.
	return info.RequiredPairingCredential() == airplay.PairingCredentialPassword
}

func restoreSavedPairing(client *airplay.AirPlayClient, saved *airplay.SavedCredentials) error {
	return client.RestorePairingCredentials(saved)
}

func readCredential(reader *bufio.Reader, prompt string) string {
	value, err := readCredentialInput(reader, prompt, os.Stdin)
	if err != nil {
		log.Fatalf("failed to read credential: %v", err)
	}
	return value
}

func readCredentialInput(reader *bufio.Reader, prompt string, input *os.File) (value string, err error) {
	fmt.Print(prompt)
	fd := int(input.Fd())
	original, terminalErr := unix.IoctlGetTermios(fd, unix.TCGETS)
	if terminalErr != nil && !errors.Is(terminalErr, unix.ENOTTY) {
		return "", fmt.Errorf("inspect credential terminal: %w", terminalErr)
	}
	if terminalErr == nil {
		interrupts := make(chan os.Signal, 1)
		signal.Notify(interrupts, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		withoutEcho := *original
		withoutEcho.Lflag &^= unix.ECHO | unix.ECHONL
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &withoutEcho); err != nil {
			signal.Stop(interrupts)
			return "", fmt.Errorf("disable credential echo: %w", err)
		}
		done := make(chan struct{})
		var restoreOnce sync.Once
		var restoreErr error
		restore := func() {
			restoreOnce.Do(func() { restoreErr = unix.IoctlSetTermios(fd, unix.TCSETS, original) })
		}
		defer func() {
			restore()
			signal.Stop(interrupts)
			close(done)
			if prompt != "" {
				fmt.Println()
			}
			if restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore credential terminal: %w", restoreErr))
			}
		}()
		go func() {
			select {
			case received := <-interrupts:
				restore()
				os.Exit(128 + int(received.(syscall.Signal)))
			case <-done:
			}
		}()
	}
	// Read the whole line rather than using fmt.Scanln, which stops at the
	// first space and would silently truncate a password containing one.
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	return line, nil
}

func selectDevice(ctx context.Context) (*airplay.AirPlayDevice, error) {
	fmt.Println("searching for Apple TVs...")
	discoverCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	devices, err := airplay.DiscoverAirPlayDevices(discoverCtx)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no Apple TVs found")
	}

	sort.Slice(devices, func(i, j int) bool {
		return compareIPs(devices[i].IP, devices[j].IP) < 0
	})

	fmt.Println("\navailable devices:")
	for i, d := range devices {
		fmt.Printf("  [%d] %q (%q) - %s\n", i+1, d.Name, d.Model, d.IP)
	}

	fmt.Print("\nselect device [1]: ")
	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)
	if input == "" {
		return &devices[0], nil
	}

	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(devices) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &devices[idx-1], nil
}

// compareIPs compares two IP address strings numerically.
func compareIPs(a, b string) int {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA == nil && ipB == nil {
		return strings.Compare(a, b)
	}
	if ipA == nil {
		return 1
	}
	if ipB == nil {
		return -1
	}
	aBytes := ipA.To16()
	bBytes := ipB.To16()
	for i := range aBytes {
		if aBytes[i] < bBytes[i] {
			return -1
		}
		if aBytes[i] > bBytes[i] {
			return 1
		}
	}
	return 0
}

func runDaemon(cfg daemon.Config) {
	d, err := daemon.New(cfg)
	if err != nil {
		log.Fatalf("[daemon] %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[daemon] shutting down...")
		cancel()
		d.Shutdown()
		<-sigCh
		log.Println("[daemon] forced exit")
		os.Exit(1)
	}()

	if err := d.Run(ctx); err != nil {
		log.Fatalf("[daemon] %v", err)
	}
}

func newCredentialStore(backend, filePath string) (*airplay.CredentialStore, error) {
	switch backend {
	case "keyring":
		kb, err := airplay.NewKeyringBackend()
		if err != nil {
			return nil, err
		}
		return airplay.NewCredentialStoreWithBackend(kb), nil
	case "file":
		return airplay.NewCredentialStore(filePath)
	default:
		return nil, fmt.Errorf("unknown credential backend %q (use \"file\" or \"keyring\")", backend)
	}
}
