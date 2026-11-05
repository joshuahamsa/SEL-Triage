"""Bounded subprocess execution for local helper programs."""

import math
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence


_PROCESS_POLL_INTERVAL_SECONDS = 0.01
_TERMINATE_GRACE_SECONDS = 0.2
_POST_KILL_REAP_SECONDS = 0.2
_READER_JOIN_SECONDS = 0.2


@dataclass(frozen=True)
class BoundedProcessResult:
    """Result of a subprocess whose pipe output was actively bounded."""

    returncode: Optional[int]
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_too_large: bool


def _drain_capped(pipe, output: bytearray, max_output_bytes: int, overflow) -> None:
    try:
        while True:
            remaining = max_output_bytes - len(output)
            chunk = pipe.read(min(64 * 1024, remaining + 1))
            if not chunk:
                return
            if len(chunk) > remaining:
                output.extend(chunk[:remaining])
                overflow.set()
                return
            output.extend(chunk)
    except (OSError, ValueError):
        # Abnormal cleanup may close the pipe while this thread is reading it.
        return


def _poll(process) -> Optional[int]:
    try:
        return process.poll()
    except OSError:
        return None


def _bounded_wait(process, timeout_seconds: float) -> bool:
    try:
        process.wait(timeout=timeout_seconds)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _reap_in_background(process) -> None:
    """Keep an unbounded kernel reap off the bounded caller path."""

    def reap() -> None:
        try:
            process.wait()
        except (OSError, subprocess.SubprocessError):
            pass

    reaper = threading.Thread(target=reap, daemon=True)
    reaper.start()


def _stop_and_reap(process) -> bool:
    """Stop the child and reap it without an unbounded caller-side wait."""

    if _poll(process) is None:
        try:
            process.terminate()
        except OSError:
            pass
    if _bounded_wait(process, _TERMINATE_GRACE_SECONDS):
        return True

    try:
        process.kill()
    except OSError:
        pass
    if _bounded_wait(process, _POST_KILL_REAP_SECONDS):
        return True

    # A real direct child should be reaped after SIGKILL. If the kernel or an
    # injected process object cannot complete promptly, preserve the bounded
    # caller contract while a daemon reaper continues the mandatory wait.
    _reap_in_background(process)
    return False


def _join_readers(readers: List[threading.Thread], timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    for reader in readers:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        reader.join(timeout=remaining)


def _write_and_close(pipe, input_bytes: bytes) -> None:
    try:
        pipe.write(input_bytes)
        pipe.close()
    except (BrokenPipeError, OSError, ValueError):
        return


def run_bounded_process(
    command: Sequence[str],
    timeout_seconds: float,
    max_output_bytes: int,
    input_bytes: Optional[bytes] = None,
    popen_factory: Callable = subprocess.Popen,
) -> BoundedProcessResult:
    """Run ``command`` while independently capping stdout and stderr."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a finite positive number")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes <= 0
    ):
        raise ValueError("max_output_bytes must be a positive integer")
    if input_bytes is not None and not isinstance(input_bytes, bytes):
        raise ValueError("input_bytes must be bytes")
    if popen_factory is None:
        popen_factory = subprocess.Popen

    process = popen_factory(
        list(command),
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        bufsize=0,
    )
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    readers: List[threading.Thread] = []
    for pipe, output in ((process.stdout, stdout), (process.stderr, stderr)):
        reader = threading.Thread(
            target=_drain_capped,
            args=(pipe, output, max_output_bytes, overflow),
            daemon=True,
        )
        reader.start()
        readers.append(reader)
    writer = None
    if input_bytes is not None:
        writer = threading.Thread(
            target=_write_and_close,
            args=(process.stdin, input_bytes),
            daemon=True,
        )
        writer.start()

    deadline = time.monotonic() + float(timeout_seconds)
    timed_out = False
    abnormal = False
    while True:
        if overflow.is_set():
            abnormal = True
            break
        if _poll(process) is not None:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            abnormal = True
            break
        overflow.wait(min(_PROCESS_POLL_INTERVAL_SECONDS, remaining))

    if abnormal:
        _stop_and_reap(process)
    else:
        if not _bounded_wait(process, _TERMINATE_GRACE_SECONDS):
            timed_out = True
            _reap_in_background(process)

    stdin_pipe = getattr(process, "stdin", None)
    if stdin_pipe is not None:
        try:
            stdin_pipe.close()
        except (OSError, ValueError):
            pass
    if writer is not None:
        writer.join(timeout=_READER_JOIN_SECONDS)
    _join_readers(readers, _READER_JOIN_SECONDS)
    # Preserve evidence that a reader did not naturally reach EOF. On POSIX,
    # closing its pipe from this thread can wake the blocked read and make the
    # thread look complete even though an inherited writer still has bytes.
    readers_incomplete_before_close = any(
        reader.is_alive() for reader in readers
    )
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
    _join_readers(readers, _READER_JOIN_SECONDS)

    # Readers must observe EOF (or be closed during bounded cleanup) before
    # classification, because a short-lived child can exit before its final
    # cap-plus-one byte has been consumed from the pipe.
    readers_incomplete = readers_incomplete_before_close or any(
        reader.is_alive() for reader in readers
    )
    output_too_large = overflow.is_set() or readers_incomplete
    if output_too_large:
        timed_out = False
    return BoundedProcessResult(
        returncode=getattr(process, "returncode", None),
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        timed_out=timed_out,
        output_too_large=output_too_large,
    )
