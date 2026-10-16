#!/usr/bin/env python3
"""Smoke test for a packaged build: python smoke_binary.py PATH_TO_torrenthub[.exe] [PATH_TO_git-remote-thub[.exe]]

Uses only the standard library, so it runs on any runner whatever Python is installed. It checks what a person
installing the package would do first: ask for the version, start a hub, ask it questions, run the MCP server and
list its tools over stdio, and run the git helper. Exit code 0 only if all of that works."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(url: str):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def mcp_tools(exe: str, gateway: str, work: str) -> list[str]:
    p = subprocess.Popen([exe, "mcp", "--gateway", gateway, "--download-root", os.path.join(work, "dl")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        def rpc(msg, want_id=None):
            p.stdin.write(json.dumps(msg) + "\n")
            p.stdin.flush()
            while want_id is not None:
                line = p.stdout.readline()
                if not line:
                    raise SystemExit("FAIL: the MCP server closed its output")
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get("id") == want_id:
                    return d
        init = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}}}, 1)
        if "result" not in init:
            raise SystemExit(f"FAIL: MCP initialize answered {init}")
        rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
        lst = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, 2)
        return [t["name"] for t in lst["result"]["tools"]]
    finally:
        p.kill()


def main() -> None:
    exe = os.path.abspath(sys.argv[1])
    helper = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else None
    out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "torrenthub" in out.stdout, f"--version: {out.returncode} {out.stdout!r} {out.stderr[-300:]!r}"
    print("version:", out.stdout.strip())

    work = tempfile.mkdtemp(prefix="thub-smoke-")
    hp, sp = free_port(), free_port()
    env = {**os.environ, "THUB_DATA": os.path.join(work, "data"), "THUB_SWARM": "libtorrent", "THUB_LISTEN_PORT": str(sp),
           "THUB_PUBLIC_URL": f"http://127.0.0.1:{hp}", "THUB_UPSTREAM": "http://127.0.0.1:9", "THUB_ANCHOR": ""}
    log = open(os.path.join(work, "serve.log"), "wb")
    hub = subprocess.Popen([exe, "serve", "--host", "127.0.0.1", "--port", str(hp)], env=env, stdout=log, stderr=log)
    base = f"http://127.0.0.1:{hp}"
    try:
        for _ in range(60):
            try:
                if get(base + "/healthz").get("ok"):
                    break
            except Exception:
                if hub.poll() is not None:
                    break
                time.sleep(1)
        else:
            raise SystemExit("FAIL: the hub did not become healthy in 60 s")
        info = get(base + "/api/thub/info")
        assert info["swarm"]["enabled"] and info["swarm"]["port"] == sp, f"the swarm is not running: {info}"
        print("hub healthy; swarm port", info["swarm"]["port"])
        assert get(base + "/api/thub/repos") == {"repos": []}
        tools = mcp_tools(exe, base, work)
        assert {"repo_info", "fetch_file", "find_repos", "whoami"} <= set(tools), tools
        print("mcp tools:", len(tools))
    except BaseException:
        log.flush()
        sys.stderr.write(open(os.path.join(work, "serve.log"), errors="replace").read()[-3000:])
        raise
    finally:
        hub.kill()
        hub.wait()
    if helper:
        h = subprocess.run([helper], capture_output=True, text=True, timeout=60)
        assert "usage: git-remote-thub" in h.stderr, f"git helper: {h.returncode} {h.stderr!r}"
        print("git-remote-thub: runs")
    print("SMOKE OK")


if __name__ == "__main__":
    main()
