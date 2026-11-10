"""Launch or stop the isolated Task112 backend and native desktop demo."""
from pathlib import Path
import fcntl
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
RUN = ROOT / "runtime"
ORIGIN = "http://127.0.0.1:18112"
SERVER = ROOT / "server.py"
APP = RUN / "Soha Task112 Demo.app" / "Contents" / "MacOS" / "soha-app"
STATE = RUN / "session.json"
KEY = RUN / "bridge.key"


def command(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip()


def owns(pid, target):
    current = command(pid)
    return current == str(target) or (target == SERVER and current.endswith(" " + str(target)))


def stop(pids):
    for label, target in (("app", APP), ("backend", SERVER)):
        pid = pids.get(label)
        if pid and owns(pid, target):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for _ in range(30):
        if not any(pids.get(label) and owns(pids[label], target)
                   for label, target in (("app", APP), ("backend", SERVER))):
            if STATE.exists() and json.loads(STATE.read_text()) == pids:
                STATE.unlink()
            return
        time.sleep(.1)
    raise SystemExit("Task112 still stopping. Retry after it exits.")


def save_state(pids):
    pending = STATE.with_suffix(".tmp")
    pending.write_text(json.dumps(pids, indent=2) + "\n")
    pending.replace(STATE)


def spawn(args, env, log_name, pass_fds=()):
    with (RUN / log_name).open("ab") as log:
        return subprocess.Popen(args, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                pass_fds=pass_fds)


def main():
    if sys.argv[1:] not in ([], ["--stop"]):
        raise SystemExit("Usage: launch.py [--stop]")
    RUN.mkdir(mode=0o700, exist_ok=True)
    with (RUN / "launch.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run(stop_requested=bool(sys.argv[1:]))


def run(stop_requested):
    pids = json.loads(STATE.read_text()) if STATE.exists() else {}
    if stop_requested:
        stop(pids)
        return
    if pids and any(pids.get(label) and owns(pids[label], target)
                    for label, target in (("app", APP), ("backend", SERVER))):
        raise SystemExit(f"Task112 already has a running process. See {STATE}")
    if not APP.is_file():
        raise SystemExit("Build the demo app first.")
    if not KEY.exists():
        with os.fdopen(os.open(KEY, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as handle:
            handle.write(secrets.token_urlsafe(32))
    env = dict(os.environ, SOHA_APP_PROFILE="task112-demo",
               SOHA_APP_NATIVE_NETWORK="disabled", SOHA_SERVER_URL=ORIGIN,
               SOHA_TASK112_DEMO_KEY=KEY.read_text().strip())
    pids = {}
    try:
        # Only the child that bound the port can signal on this inherited descriptor.
        with tempfile.TemporaryFile(dir=RUN) as ready:
            fd = ready.fileno()
            backend = spawn([sys.executable, str(SERVER)],
                            {**env, "SOHA_TASK112_READY_FD": str(fd)}, "backend.log", pass_fds=(fd,))
            pids["backend"] = backend.pid
            save_state(pids)
            for _ in range(40):
                if backend.poll() is not None:
                    raise RuntimeError("Task112 backend exited. Check backend.log.")
                if os.pread(fd, 1, 0) == b"1" and backend.poll() is None:
                    break
                time.sleep(.15)
            else:
                raise RuntimeError("Task112 backend did not become ready.")
        app = spawn([str(APP)], env, "app.log")
        pids["app"] = app.pid
        save_state(pids)
        time.sleep(1)
        if app.poll() is not None:
            raise RuntimeError("Task112 App exited. Check app.log.")
        if backend.poll() is not None:
            raise RuntimeError("Task112 backend exited. Check backend.log.")
    except BaseException:
        stop(pids)
        raise
    print(f"Task112 demo running at {ORIGIN}. Process IDs: {pids}")


if __name__ == "__main__":
    main()
