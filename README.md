# doubletake

AirPlay screen mirroring sender for Linux. Streams your desktop to an Apple TV using the AirPlay mirroring protocol.

## Hardened fork

Modified by Y4nKorzun on 2026-10-18, based on upstream **v0.5.0**.
The upstream LGPL-3.0-or-later license and incorporated GPL notices are retained.

This fork verifies the receiver's SRP proof and signed identity during pairing,
stores that identity with the pairing credentials, and verifies it on reconnect.
Verification failures and unavailable credential storage stop the connection.
Credentials are replaced atomically with owner-only permissions. Debug logs do
not print session keys or plaintext media samples. Receiver-supplied binary
plists have explicit size, graph-expansion, and nesting limits before decoding.

First-time connections require authenticated PIN/password pairing. PIN-less
transient pairing, plaintext control sessions, and `-no-encrypt` are disabled.
A receiver that supports only transient pairing or plaintext control is not
supported by this fork. A modern receiver's playback password remains separate
from its on-screen pairing PIN.

For the restricted launch profile, use Linux x86_64 with a Wayland screencast
portal, Landlock ABI 6 or newer, bubblewrap, xdg-dbus-proxy, and a systemd user
session with delegated resource controllers. Build with the exact Go 1.27.2 SDK:

```sh
python3 -I tools/build_safe.py --go ~/.cache/development-tools/go1.27.2/bin/go
```

The builder uses verified disk-backed temporary storage, persistent Go caches,
read-only modules, and no CGO. The launcher checks a source and binary digest
receipt and refuses a stale or modified artifact. It accepts a system-installed
root-owned D-Bus proxy, or the cached Arch 0.1.9 executable with the pinned digest
in `tools/run_safe.py`.

Enable **AirPlay Receiver** on the Mac, use a trusted local network, and pair
with the code displayed on that specific Mac. Use its numeric private IPv4
address. Set **Allow AirPlay for** to **Anyone on the Same Network**: Apple's
**Current User** mode is restricted to devices signed in to the same Apple
Account. See [Apple's receiver setup guide](https://support.apple.com/guide/mac-help/stream-video-and-audio-with-airplay-mchld7e543a0/mac).
An HTTP 403 response to the PIN request can indicate a receiver access-policy
restriction; check that setting before retrying.

First send generated video without accessing a real screen:

```sh
python3 -I tools/run_safe.py MAC_IP --pair --synthetic
```

Later connections verify the saved receiver identity. To share a real screen:

```sh
python3 -I tools/run_safe.py MAC_IP
```

The profile requests screen selection through the desktop portal on each run,
without storing a persistent screen grant. It disables audio and hardware
encoding. The sandbox exposes neither the host home nor direct Wayland, X11,
audio, GPU, or secret-service access. Landlock also blocks host abstract UNIX
sockets and signals outside the sandbox. The D-Bus proxy permits only screencast
operations and their request/session lifecycle. The whole sender process tree is
limited to 768 MiB RAM, 128 MiB swap, 96 tasks, and two CPUs' worth of runtime.
Interrupting the launcher stops its owned systemd scope before temporary cleanup.

Pairing credentials persist only in `~/.local/share/doubletake-safe/config`.
The network namespace is shared for AirPlay TCP/UDP: this profile is not an
outbound network firewall. Pair only with a device you control on a trusted LAN.
The direct CLI, audio capture, daemon, and optional GPU paths have broader access
than this launch profile.

Upstream credentials lack the verified receiver key and require one explicit
`-pair` after checking the destination device. The daemon also stops on an
identity mismatch; repair pairing through the CLI only after checking the Mac.
Optional system-keyring storage remains available with `-cred-backend keyring`.
For direct CLI use, `-code` / `DOUBLETAKE_CODE` supplies the pairing PIN;
`-password` / `DOUBLETAKE_PASSWORD` supplies a separate playback password. Digest
authentication is permitted only after receiver verification and control-channel
encryption. Receivers demanding Digest before pairing are refused. Interactive
PINs and passwords are hidden while typing, with terminal state restored on exit.

Focused security tests cover forged pairing proofs/signatures, credential errors,
Digest disclosure, malformed plists, microphone fallback, and resource bounds.
Native sandbox checks cover filesystem/desktop IPC isolation, filtered portal
access, and the kernel's actual cgroup limits. These checks do not constitute a
complete security audit. The device list below records upstream compatibility.

Local validation on 2026-10-18: the Go suite passed 988 tests/subtests with eight
optional/platform-specific skips; all 32 build/launcher/isolation checks passed.
`go mod verify` passed, and `govulncheck` found no reachable Go vulnerabilities.
Encrypted synthetic streaming to local test receivers passed. A restricted
launch successfully decoded a native Mac16,10's `/info` response, then stopped
cleanly when that Mac denied the PIN request with HTTP 403. No screen or audio
was captured. Successful native pairing and real-screen streaming remain
unverified until the receiver permits pairing and its on-screen code is entered.

## Features

- Full AirPlay mirroring protocol (RTSP/HTTP + encrypted video stream)
- FairPlay SAP authentication (clean Go implementation)
- SRP-6a pairing with PIN and persistent credential storage
- Wayland (PipeWire/xdg-desktop-portal) and X11 screen capture
- H.264 encoding with NVENC, VA-API, OpenH264, and x264
- Capability-gated HEVC Main10/high-resolution encoding with NVENC or x265
- ChaCha20-Poly1305 stream encryption
- mDNS device discovery
- Daemon mode with multi-target streaming control (`doubletake-ctl`)
- In-process test receiver for hardware-free pairing and media-flow tests
- Automatic connection-aware screen/audio latency policy with an optional `-target-latency-ms` override
- KDE Plasma widget for quick access (see [plasmoid/](plasmoid/))

## Requirements

- Go 1.25+
- GStreamer 1.0 (with plugins-base, plugins-good, plugins-bad, plugins-ugly, libav)
- PulseAudio utilities (`pactl`; `pulseaudio-utils` on Ubuntu/Debian or the equivalent package on other distributions)
- PipeWire (Wayland) or X11 for screen capture

### Ubuntu/Debian

```sh
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
  gstreamer1.0-plugins-ugly gstreamer1.0-libav pulseaudio-utils
```

### Arch Linux

```sh
sudo pacman -S gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad \
  gst-plugins-ugly gst-libav libpulse
```

The `openh264` encoder requires the GStreamer `openh264enc` element, normally
provided by the plugins-bad package. Check availability with
`gst-inspect-1.0 openh264enc`.

You can also install from the AUR:

The following packages install upstream Doubletake and do **not** include this
fork's changes. Build from this fork's source to obtain the hardening changes.

- [`doubletake`](https://aur.archlinux.org/packages/doubletake) (stable release package)
- [`doubletake-git`](https://aur.archlinux.org/packages/doubletake-git) (latest from git)
- [`doubletake-bin`](https://aur.archlinux.org/packages/doubletake-bin) (prebuilt binary package)

## Upstream Tested Devices

These are devices reported as tested by upstream Doubletake.

- AppleTV3,2 (2013 3rd generation)
- AppleTV11,1 (4K, 2021 2nd gen)
- AppleTV14,1 (4K, 2022 3rd gen) + Homepod (1st gen)
- AppleTV14,1 (4K, 2022 3rd gen)
- Mac17,2 (MacBook Pro, M5 14")
- Mac16,10 (Mac mini, M4)
- Roku Streaming Stick 4K (3820R2)
- Samsung TV TU8300 Series 4K UHD
- Hisense 55A6QU
- Xiaomi 4K HDR TV (AFTBR92D74) (currently non-functional, see [#4](https://github.com/omarroth/doubletake/issues/4))

## Build

```sh
make
```

This builds the three binaries into `bin/`:

- `bin/doubletake`
- `bin/doubletake-ctl`
- `bin/doubletake-test-receiver`

## Install

Install binaries and man pages (default prefix: `/usr/local`):

```sh
sudo make install
```

Use a custom prefix if needed:

```sh
make install PREFIX=$HOME/.local
```

Uninstall:

```sh
sudo make uninstall
```

Run tests:

```sh
make test
```

### Optional AAC-ELD support

Doubletake selects screen audio from the receiver's advertised
`supportedFormats.screenStream` mask. Default builds use the built-in ALAC
encoder when the receiver advertises it. AAC-ELD remains an explicit opt-in
because it depends on the system `libfdk-aac` development files and cgo:

```sh
CGO_ENABLED=1 go build -tags fdk_aac -o bin/doubletake ./cmd/doubletake
```

Install the package that provides the `fdk-aac` pkg-config file and headers for
your distribution before running that command. A default build reports a clear
error if advertised capabilities select AAC-ELD. A nonzero screen-audio mask
which advertises neither ALAC nor AAC-ELD is also rejected instead of silently
sending an unadvertised format. Use `-no-audio` to keep testing pairing, timing,
and video when the advertised audio format is unavailable.

## Firewall

doubletake binds three consecutive local UDP ports for each stream:

- `N`: timing. A receiver-initiated NTP session probes this port during SETUP.
- `N+1`: audio control and receiver retransmission requests.
- `N+2`: outgoing audio data.

PTP and sender-initiated NTP sessions do not require a new inbound timing
connection, but the receiver can still send audio retransmission requests to
the control port. The event and video data channels are outbound TCP
connections from doubletake to ports returned by the receiver. Doubletake does
not listen for inbound TCP connections.

No router port forwarding or Internet exposure is needed. If the host firewall
allows local-network traffic, no firewall configuration is necessary. With a
default-deny host firewall, use `-port-range MIN-MAX` to replace unpredictable
ephemeral UDP ports with a range you can allow from the receiver. The range
must contain at least three ports:

```sh
doubletake -target 192.168.1.77 -port-range 60000-60010
```

Daemon mode uses the same range for every managed stream. Reserve at least
three available ports per receiver that may stream simultaneously.

For example, restrict a UFW rule to the receiver's address:

```sh
sudo ufw allow from 192.168.1.77 proto udp to any port 60000:60010
```

Add a rule for each receiver, or use the trusted LAN subnet as the source. For
nftables/firewalld, add an equivalent inbound UDP rule for the selected source
and range.

NTP and PTP use the same presentation policy; the timing protocol only changes
how timestamps are represented. In automatic mode, an ordinary connection uses
a 75 ms video lead and an 85 ms screen-audio lead.

## Password-protected receivers

If the receiver has **Require Password** enabled (on an Apple TV: Settings →
AirPlay and HomeKit), it challenges the mirroring `SETUP` request with HTTP
Digest auth and mirroring fails with `HTTP 401` until doubletake answers it.
Pass the password with `-code`:

```sh
DOUBLETAKE_CODE='...' doubletake -target 192.168.1.77
```

`-code` carries whatever the receiver is asking for — the onscreen pairing PIN
during `-pair`, or the fixed password when "Require Password" is enabled.
`$DOUBLETAKE_CODE` is preferred over the flag: a command line is visible to
other users via `ps` and lands in shell history. The environment variable takes
precedence when both are set.

Pairing and Digest authentication use separate credentials on modern receivers.
The configured playback password is retained for Digest, while first-time
pairing separately requests the PIN displayed on the receiver. A pairing PIN
does not replace the playback password. Supplying `-code` does not by itself
replace a saved receiver identity; only an explicit `-pair` may do that.

When the capability policy selects first-party CoreUtils/HAP pairing, a
configured fixed password is reserved for Digest authentication and is never
reused as an SRP pairing PIN, including with `-pair`. A legacy/HKP pairing flow
may consume the same entered value during both SRP and Digest when its protocol
requires it.

The CLI and daemon distinguish pairing PIN prompts from playback-password
prompts. In the Plasma applet, an on-screen PIN uses a visible four-digit field,
while a configured password uses an unrestricted masked field. The daemon exposes
the distinction while retaining `doubletake-ctl pin <PIN-or-password>` for
command compatibility when exactly one receiver is waiting. With concurrent
prompts, submit each value with `doubletake-ctl connect TARGET PIN-or-password`.

One thing that makes this confusing to diagnose: **"Require Password" is a
fixed password you set, not a rotating onscreen code.** Nothing appears on the
TV during `-pair`, and the prompt is asking for that configured password.

Run with `-debug` to see the challenge and whether the retry was accepted.

## Usage

```sh
# Discover Apple TVs on the network and stream
doubletake

# Disable audio for video-only mirroring
doubletake -no-audio

# Connect to a specific Apple TV
doubletake -target 192.168.1.77

# First-time pairing with PIN (saves credentials for reuse)
doubletake -target 192.168.1.77 -pair

# Use saved credentials
doubletake -target 192.168.1.77 -creds airplay-credentials.json

# Adjust stream settings (bitrate 0 = auto)
doubletake -target 192.168.1.77 -fps 30 -bitrate 0

# Force a lower bitrate on weaker Wi-Fi
doubletake -target 192.168.1.77 -bitrate 4500

# Override the automatic audio/video playout latencies with one joint value
doubletake -target 192.168.1.77 -target-latency-ms 100

# Hardware encoding
doubletake -target 192.168.1.77 -hwaccel nvenc   # NVIDIA
doubletake -target 192.168.1.77 -hwaccel vaapi   # Intel/AMD

# OpenH264 software encoding
doubletake -target 192.168.1.77 -hwaccel openh264

# Automatic H.264 compatibility mode is the default
doubletake -target 192.168.1.77

# Force one codec (HEVC uses the receiver's maximum canvas)
doubletake -target 192.168.1.77 -video-codec hevc
doubletake -target 192.168.1.77 -video-codec h264

# Debug mode (verbose protocol logging)
doubletake -target 192.168.1.77 -debug

# Run daemon mode and control from a second shell
doubletake -daemonize -port-range 60000-60010
doubletake-ctl status
doubletake-ctl connect 192.168.1.77
doubletake-ctl connect 192.168.1.133
doubletake-ctl disconnect 192.168.1.77
doubletake-ctl disconnect
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Apple TV IP (skip mDNS discovery) |
| `-port` | 7000 | AirPlay port |
| `-code` | | Pairing PIN shown on the receiver, or its configured password when "Require Password" is enabled (see [Password-protected receivers](#password-protected-receivers)); prefer `$DOUBLETAKE_CODE` |
| `-port-range` | | Local UDP range for timing/audio and receiver control traffic (at least 3 ports) |
| `-cred-backend` | `file` | Credential backend (`file` or `keyring`) |
| `-creds` | `~/.config/doubletake/credentials.json` | Credentials file path |
| `-pair` | false | Force new pairing |
| `-fps` | 30 | Frames per second |
| `-bitrate` | 0 | Video bitrate in kbps (`0` = auto) |
| `-target-latency-ms` | 0 | Joint audio/video playout latency override in milliseconds (`0` = automatic wired/wireless profiles with separate audio/video defaults) |
| `-hwaccel` | auto | Encoder preference: `auto`, `nvenc`, `vaapi`, `openh264`, `none` |
| `-video-codec` | auto | Screen codec: compatible H.264 `auto`, forced `h264`, or forced `hevc` |
| `-no-encrypt` | false | Rejected by this fork; media encryption is required |
| `-direct-key` | false | Use `shk`/`shiv` directly without SHA-512 derivation |
| `-no-audio` | false | Disable audio streaming |
| `-test` | false | Use synthetic video source |
| `-daemonize` | false | Run as background daemon with Unix socket control interface |
| `-socket` | `$XDG_RUNTIME_DIR/doubletake.sock` | Daemon control socket path |
| `-debug` | false | Verbose debug logging |

Only `-hwaccel auto` tries fallback encoders, in the order `vulkanh264enc`,
`nvh264enc`, `vah264enc`, `openh264enc`, then `x264enc`. Explicit selections
fail if their required GStreamer encoder is unavailable; `none` forces x264 for
H.264 or x265 for explicitly requested HEVC.
The normal `-video-codec auto` path uses H.264 at the receiver's nominal canvas
for compatibility across AirPlay receiver generations. Explicit
`-video-codec hevc` remains available with `nvh265enc` or `x265enc`; use
`-hwaccel none` to force the software path.

Main10 alone does not turn an SDR X11 or portal capture into HDR: doubletake
preserves encoder-provided HDR SEI but does not invent PQ/HLG mastering metadata
or relabel SDR colors as HDR.

### Daemon Control (`doubletake-ctl`)

```sh
doubletake-ctl status
doubletake-ctl discover
doubletake-ctl devices
doubletake-ctl connect [target] [PIN-or-password]
doubletake-ctl pin <PIN-or-password>
doubletake-ctl disconnect [target]
doubletake-ctl mute [target]
doubletake-ctl unmute [target]
```

- `disconnect` without a target stops all active streams.
- `disconnect <target>` stops only that receiver.
- `mute`/`unmute` can operate globally or per target.
- `pin` retains its historical command name, but submits whichever credential
  the daemon requests: an on-screen PIN or a configured password. It is
  targetless and therefore requires exactly one waiting receiver; use
  `connect <target> <PIN-or-password>` when multiple receivers are waiting.

Daemon streams are grouped by codec and the normalized even-sized canvas resolved
during each receiver's SETUP. Targets with the same key share one capture and
encoder; targets with a different codec or canvas use independent encoders,
so connection order does not determine another receiver's size. For example, a
receiver reporting a 1920x1080 canvas and a 3840x2160 maximum joins the
1920x1080 H.264 group in automatic mode. An explicit HEVC request uses the
maximum canvas and forms a separate group.
Fan-out uses a bounded queue per target within each group. A
stalled target is detached when its queue fills, without blocking peers that
share the encoder. Other canvas groups continue independently as well.

## Disclaimer

The majority of code for this project was written by LLMs. I've read through the code to make sure there's nothing obviously stupid, but if you're in a production or security-sensitive environment and need to use AirPlay (for whatever reason), do not use this project.

Since I assume most of the code for this project was trained from [UxPlay](https://github.com/FDH2/UxPlay) and similar projects, I've provided this project under a similar license. Most of the reverse engineering work has already been done by many other people and this project would not be possible without them.

## License

This project is licensed under the [GNU Lesser General Public License v3.0 or later](LICENSE) (`LGPL-3.0-or-later`). See the LICENSE file for the LGPL terms and [COPYING.GPL](COPYING.GPL) for the incorporated GPLv3 terms.

Releases v0.3.2 and earlier were provided under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`).
