"""Bound trusted subprocess output and retain ownership through pipe cleanup.

POSIX children start in a new session; cleanup kills that exact process group,
including descendants after its leader exits. This is lifecycle containment,
not a sandbox: a deliberately escaping descendant is outside this contract.
Windows uses taskkill's tree stop and reports failed cleanup when unavailable.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time

_GROUP_ENV = '_PCAP_EVIDENCE_OWNED_PROCESS_GROUP'


@dataclass(frozen=True)
class Result:
    returncode: int | None
    reason: str | None
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float
    output_bytes: int


def stop_owned_process(proc, *, posix=None, kill_group=None):
    use_group = os.name == 'posix' if posix is None else posix
    if use_group:
        try:
            (os.killpg if kill_group is None else kill_group)(proc.pid, signal.SIGKILL)
            return True
        except ProcessLookupError:
            if proc.poll() is not None:
                return True
        except PermissionError:
            if proc.poll() is not None:
                return True
    elif os.name == 'nt':
        try:
            stopped = subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=5, check=False)
            if stopped.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
        # Direct child exit cannot prove descendant tree cleanup on Windows.
        if proc.poll() is None:
            proc.kill()
        return False
    if proc.poll() is not None:
        return True
    try:
        proc.kill()
        return True
    except ProcessLookupError:
        return True
    except PermissionError:
        return proc.poll() is not None


def run(command, *, cwd=None, env=None, timeout=300, max_output_bytes=8*1024*1024,
        stdout=None, stderr=None):
    """Drain both pipes under one aggregate byte cap; never write beyond it.

Sinks are caller-owned binary streams. With no sink the bounded bytes are
returned. BaseException is re-raised after stop/reap/drain, with the adverse
``process_result`` attached so a receipt owner can preserve the attempted run.
"""
    if not command or timeout <= 0 or max_output_bytes < 1:
        raise ValueError('positive timeout/output budget and command required')
    started = time.monotonic()
    environment = dict(os.environ if env is None else env)
    inherited_group = (os.name == 'posix' and environment.get(_GROUP_ENV) == str(os.getpgrp())
                       and os.getsid(0) == os.getpgrp())
    launch = command
    if os.name == 'posix' and not inherited_group:
        # The new group ID is known only inside the child. This tiny exec shim
        # publishes that exact ID before the trusted executable starts, keeping
        # later nested runners inside the outer owner's containment boundary.
        executable = command[0]
        if os.path.dirname(executable) and not os.path.isabs(executable):
            executable = str(Path(cwd or os.getcwd()) / executable)
        resolved = shutil.which(executable, path=environment.get('PATH'))
        if resolved is None:raise FileNotFoundError('executable unavailable: '+command[0])
        launch = [sys.executable,str(Path(__file__).resolve()),'--owned-exec',resolved,*command[1:]]
    threads = []
    buffers = [bytearray(), bytearray()]
    lock = threading.Lock()
    limited = threading.Event()
    pump_failed = threading.Event()
    retained = 0
    reason = None
    error = None

    def pump(pipe, index, sink):
        nonlocal retained
        try:
            while chunk := os.read(pipe.fileno(), 8192):
                with lock:
                    room = max_output_bytes - retained
                    keep = chunk[:room]
                    if sink is None:
                        buffers[index].extend(keep)
                    else:
                        sink.write(keep)
                        sink.flush()
                    retained += len(keep)
                    if len(chunk) > room:
                        limited.set()
                # Continue draining while the owner stops the group. Closing
                # early would hide terminal bytes or strand a pipe writer.
        except Exception:
            pump_failed.set()
        finally:
            pipe.close()

    proc = subprocess.Popen(launch, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell=False, start_new_session=os.name == 'posix' and not inherited_group)
    try:
        for index, (pipe, sink) in enumerate(((proc.stdout, stdout), (proc.stderr, stderr))):
            thread = threading.Thread(target=pump, args=(pipe, index, sink), daemon=True)
            threads.append(thread)
            thread.start()
        while True:
            if limited.is_set():
                reason = 'output_budget'; break
            if pump_failed.is_set():
                reason = 'output_io_error'; break
            if time.monotonic() - started >= timeout:
                reason = 'timeout'; break
            if proc.poll() is not None and not any(t.is_alive() for t in threads):
                break
            time.sleep(0.005)
    except BaseException as caught:
        error = caught
        reason = 'interrupted' if isinstance(caught, KeyboardInterrupt) else 'runner_exception'
    finally:
        # Always close the group, even after a clean leader exit: descendants
        # can survive without inheriting either output descriptor.
        if not stop_owned_process(proc, posix=os.name == 'posix' and not inherited_group):
            reason = 'stop_failed'
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            stop_owned_process(proc, posix=os.name == 'posix' and not inherited_group)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                reason = 'stop_failed'
        deadline = time.monotonic() + 2
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(t.is_alive() for t in threads):
            reason = reason or 'pipe_not_closed'
        for pipe in (proc.stdout, proc.stderr):
            if not pipe.closed and not any(t.is_alive() for t in threads):
                pipe.close()
        # An exited producer can cross the cap before the monitor samples it.
        if limited.is_set() and reason is None:
            reason = 'output_budget'
        if pump_failed.is_set() and reason is None:
            reason = 'output_io_error'
    result = Result(proc.returncode, reason, bytes(buffers[0]), bytes(buffers[1]),
                    round(time.monotonic()-started, 6), retained)
    if error is not None:
        error.process_result = result
        raise error
    return result


if __name__ == '__main__':
    if os.name != 'posix' or len(sys.argv)<3 or sys.argv[1]!='--owned-exec' or os.getpgrp()!=os.getpid():
        raise SystemExit('owned exec requires a newly created POSIX group')
    os.environ[_GROUP_ENV] = str(os.getpgrp())
    os.execvpe(sys.argv[2],sys.argv[2:],os.environ)
