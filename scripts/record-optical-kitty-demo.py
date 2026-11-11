#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
FPS = 30
GIF_FPS = 6


def run(*args, **kwargs):
    return subprocess.check_output(args, **kwargs)


def record(scratch):
    scratch = Path(scratch)
    work = scratch / "work"
    work.mkdir()
    (work / "briefing.bin").write_bytes(os.urandom(256 * 1024))
    client = scratch / "dud"
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("DUD_") and key not in ("NO_COLOR", "FORCE_COLOR")}
    env["DUD_HOME"] = str(scratch / "state")
    env["GOCACHE"] = "/tmp/dud-go-build-cache"
    subprocess.run(["go", "-C", str(ROOT / "client"), "build", "-o", str(client), "./cmd/dud"],
                   env=env, check=True)
    capture_program = scratch / "record-window"
    subprocess.run(["xcrun", "swiftc", "-parse-as-library", "-swift-version", "5",
                    "-target", os.uname().machine + "-apple-macos15.0",
                    "-module-cache-path", "/tmp/dud-swift-module-cache",
                    str(ROOT / "scripts" / "record-demo-window.swift"),
                    "-o", str(capture_program)], check=True)
    socket = "unix:" + str(scratch / "control.sock")

    def remote(*args):
        return run("kitty", "@", "--to", socket, *args, text=True, timeout=10)

    def wait_for(pattern):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            content = remote("get-text")
            if re.search(pattern, content):
                return
            time.sleep(0.1)
        raise RuntimeError("Missing TUI screen: " + pattern + "\n" + content)

    def key(value):
        remote("send-key", value)

    def type_text(value):
        for char in value:
            remote("send-text", "--", char)
            time.sleep(0.035)

    with (scratch / "kitty.log").open("w") as log:
        process = subprocess.Popen([
            "kitty", "-c", "NONE", "--listen-on", socket, "--title", "DUD optical demo",
            "-o", "allow_remote_control=socket-only", "-o", "remember_window_size=no",
            "-o", "initial_window_width=1200", "-o", "initial_window_height=850",
            "-o", "font_size=18", "-o", "background=#303446", "-o", "foreground=#c6d0f5",
            "-o", "window_padding_width=12", "-o", "confirm_os_window_close=0",
            "--directory", str(work), str(client), "--tui",
        ], env=env, stdout=log, stderr=subprocess.STDOUT)
        recorder = None
        capture_started = None
        try:
            deadline = time.monotonic() + 20
            while not (scratch / "control.sock").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Kitty did not open its control socket.\n" + (scratch / "kitty.log").read_text())
                time.sleep(0.1)
            wait_for(r"7\) tools")
            windows = json.loads(remote("ls"))
            window_id = str(windows[0]["platform_window_id"])
            ready = scratch / "capture.ready"
            recorder = subprocess.Popen([
                str(capture_program), window_id, str(scratch / "native.mp4"), "35", str(ready),
            ], stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 20
            while not ready.exists():
                if recorder.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Window recording did not start.\n" + (scratch / "kitty.log").read_text())
                time.sleep(0.1)
            capture_started = time.monotonic()
            time.sleep(2)
            type_text("1")
            wait_for("Share by opaque ID")
            key("down")
            time.sleep(2)
            key("enter")
            wait_for("Send message")
            key("down")
            time.sleep(1)
            key("enter")
            wait_for("QR profile")
            type_text("briefing.bin")
            time.sleep(3)
            key("ctrl+s")
            wait_for("Enter passphrase")
            type_text("demo-optical-passphrase")
            key("enter")
            wait_for("Confirm passphrase")
            type_text("demo-optical-passphrase")
            key("enter")

            # A white quiet zone identifies actual Kitty image presentation.
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                probe = scratch / "probe.png"
                remote("screenshot", str(probe))
                pixel = run("ffmpeg", "-v", "error", "-i", str(probe), "-vf",
                            "crop=1:1:40:40,format=rgb24", "-f", "rawvideo", "-")
                if len(pixel) == 3 and min(pixel) > 240:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("Kitty did not display optical QR images.")
            qr_start = time.monotonic() - capture_started
            time.sleep(6)
            qr_end = time.monotonic() - capture_started
            type_text("q")
            wait_for("Remote receipt is unconfirmed")
            time.sleep(3)
            recorder.wait(timeout=40)
            if recorder.returncode:
                raise RuntimeError("Native window recording failed.\n" + (scratch / "kitty.log").read_text())
        finally:
            if recorder and recorder.poll() is None:
                recorder.terminate()
                recorder.wait(timeout=10)
            if process.poll() is None:
                try:
                    remote("close-window", "--match", "id:1")
                    process.wait(timeout=10)
                except (subprocess.SubprocessError, OSError):
                    process.terminate()
                    process.wait(timeout=10)
    assets = ROOT / "docs" / "assets"
    assets.mkdir(exist_ok=True)
    movie = scratch / "verified.mp4"
    gif = assets / "optical-kitty.gif"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(scratch / "native.mp4"),
                    "-t", str(qr_end + 3),
                    "-vf", "scale=1200:-2:flags=lanczos,fps=30", "-c:v", "libx264",
                    "-crf", "18", "-preset", "medium", "-pix_fmt", "yuv420p",
                    "-movflags", "+faststart", str(movie)], check=True)
    hashes = run("ffmpeg", "-v", "error", "-ss", str(qr_start + 1), "-t", "3",
                 "-i", str(movie), "-vf",
                 "crop=200:200:100:150,format=gray,lut=y='if(gt(val,128),255,0)'",
                 "-f", "framemd5", "-", text=True)
    unique = {line.rsplit(",", 1)[-1].strip() for line in hashes.splitlines() if not line.startswith("#")}
    if len(unique) < 75:
        raise RuntimeError(f"Only {len(unique)} distinct QR frames in three seconds of native video.")
    preview = scratch / "preview.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(movie), "-vf",
                    f"scale=960:-2:flags=lanczos,fps={GIF_FPS}",
                    "-c:v", "libx264", "-crf", "18", str(preview)], check=True)
    palette = scratch / "palette.png"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(preview), "-vf",
                    "palettegen=stats_mode=diff", "-frames:v", "1", str(palette)], check=True)
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(preview), "-i", str(palette),
                    "-lavfi", "paletteuse=dither=none", "-loop", "0", str(gif)], check=True)
    if gif.stat().st_size > 10 * 1024 * 1024:
        raise RuntimeError("The GIF exceeds GitHub's 10 MiB image limit.")
    print(f"Recorded {gif} at {GIF_FPS} FPS from continuous {FPS} FPS capture; {len(unique)} distinct QR frames verified in three seconds.")


if __name__ == "__main__":
    for program in ("go", "kitty", "age", "ffmpeg", "xcrun"):
        if not shutil.which(program):
            raise SystemExit(program + " is required to record the optical demo.")
    with tempfile.TemporaryDirectory(prefix="dud-kitty-demo-", dir="/tmp") as scratch:
        record(scratch)
