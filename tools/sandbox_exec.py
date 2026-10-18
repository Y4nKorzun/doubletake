#!/usr/bin/python3 -I
"""Confine desktop IPC with Landlock, then execute an absolute command."""

from __future__ import annotations

import ctypes
import os
import platform
import sys


SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1
LANDLOCK_SCOPE_SIGNAL = 2
PR_SET_NO_NEW_PRIVS = 38


class LandlockRuleset(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


def checked_call(result: int, operation: str) -> int:
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, f"{operation}: {os.strerror(error)}")
    return result


def confine_desktop_ipc() -> int:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("desktop IPC confinement requires Linux x86_64")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int

    abi = checked_call(libc.syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET), ctypes.c_void_p(), ctypes.c_size_t(0),
        ctypes.c_uint(LANDLOCK_CREATE_RULESET_VERSION),
    ), "query Landlock ABI")
    if abi < 6:
        raise RuntimeError(f"Landlock ABI 6 or newer is required; kernel provides ABI {abi}")

    checked_call(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "enable no-new-privileges")
    ruleset = LandlockRuleset(scoped=LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL)
    descriptor = checked_call(libc.syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET), ctypes.byref(ruleset), ctypes.c_size_t(ctypes.sizeof(ruleset)), ctypes.c_uint(0),
    ), "create desktop IPC ruleset")
    try:
        checked_call(libc.syscall(
            ctypes.c_long(SYS_LANDLOCK_RESTRICT_SELF), ctypes.c_int(descriptor), ctypes.c_uint(0),
        ), "enforce desktop IPC ruleset")
    finally:
        os.close(descriptor)
    return abi


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    if not arguments or not os.path.isabs(arguments[0]):
        raise RuntimeError("an absolute executable path is required")
    confine_desktop_ipc()
    os.execv(arguments[0], arguments)
    raise RuntimeError("sandbox executable did not replace the bootstrap")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"Sandbox confinement refused: {error}")
