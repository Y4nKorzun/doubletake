package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func securityCredentialPTY(t *testing.T) (*os.File, *os.File, *unix.Termios) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "credential-pty-master")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	original, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	original.Lflag |= unix.ECHO
	if err := unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, original); err != nil {
		t.Fatal(err)
	}
	return master, slave, original
}

func securityWaitForCredentialEcho(t *testing.T, input *os.File, enabled bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		terminal, err := unix.IoctlGetTermios(int(input.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if (terminal.Lflag&unix.ECHO != 0) == enabled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal echo did not become enabled=%t", enabled)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSecurityCredentialTTYDoesNotEchoAndRestoresState(t *testing.T) {
	master, slave, original := securityCredentialPTY(t)
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := readCredentialInput(bufio.NewReader(slave), "", slave)
		done <- result{value, err}
	}()
	securityWaitForCredentialEcho(t, slave, false)
	const password = "private playback password"
	if _, err := master.Write([]byte(password + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.value != password {
			t.Fatalf("credential read = (%q, %v)", got.value, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("credential read did not complete")
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || *after != *original {
		t.Fatalf("terminal state was not restored: %v", err)
	}
	var echoed [128]byte
	fd := int(master.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	count, err := unix.Read(fd, echoed[:])
	if count > 0 || (!errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK)) {
		t.Fatalf("credential was echoed: %q, error %v", echoed[:max(count, 0)], err)
	}
}

func TestSecurityCredentialRedirectedInputPreservesSpaces(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output.Close()
	value, err := readCredentialInput(bufio.NewReader(strings.NewReader("password with spaces\r\n")), "", input)
	if err != nil || value != "password with spaces" {
		t.Fatalf("redirected credential = (%q, %v)", value, err)
	}
}

func TestSecurityCredentialTTYRestoresOnTermination(t *testing.T) {
	for _, interrupt := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(interrupt.String(), func(t *testing.T) {
			_, slave, original := securityCredentialPTY(t)
			process := exec.Command(os.Args[0], "-test.run=^TestSecurityCredentialTTYSignalHelper$")
			process.Stdin = slave
			process.Stdout, process.Stderr = io.Discard, io.Discard
			process.Env = append(os.Environ(), "DOUBLETAKE_TEST_TTY_SIGNAL=1")
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- process.Wait() }()
			waited := false
			t.Cleanup(func() {
				if !waited {
					process.Process.Kill()
					<-done
				}
			})
			securityWaitForCredentialEcho(t, slave, false)
			if err := process.Process.Signal(interrupt); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				waited = true
				if process.ProcessState.ExitCode() != 128+int(interrupt) {
					t.Fatalf("termination exit code = %d", process.ProcessState.ExitCode())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("credential reader did not stop on termination")
			}
			after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || *after != *original {
				t.Fatalf("termination did not restore terminal state: %v", err)
			}
		})
	}
}

func TestSecurityCredentialTTYSignalHelper(t *testing.T) {
	if os.Getenv("DOUBLETAKE_TEST_TTY_SIGNAL") != "1" {
		return
	}
	if _, err := readCredentialInput(bufio.NewReader(os.Stdin), "", os.Stdin); err != nil {
		t.Fatal(err)
	}
	t.Fatal("credential reader returned without a termination signal")
}
