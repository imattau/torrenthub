#!/bin/sh
# Build the package, install the wheel into a clean virtualenv at the locked versions, and run it.
# This is what "it works when installed" means; running from a checkout proves less.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'kill ${pid:-0} 2>/dev/null || true; rm -rf "$tmp"' EXIT
python3 -m venv "$tmp/build" && "$tmp/build/bin/pip" install -q build
(cd "$here" && "$tmp/build/bin/python" -m build --outdir "$tmp/dist" . >/dev/null)
ls "$tmp/dist"
python3 -m venv "$tmp/venv"
wheel=$(ls "$tmp/dist"/*.whl)
"$tmp/venv/bin/pip" install -q -c "$here/lock/runtime.txt" "$wheel[swarm,fast,relay]"
"$tmp/venv/bin/torrenthub" --version
"$tmp/venv/bin/git-remote-thub" >/dev/null 2>&1 && { echo "git-remote-thub should refuse to run without arguments"; exit 1; } || true
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
export THUB_DATA="$tmp/data" THUB_SWARM=libtorrent THUB_LISTEN_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])') THUB_PUBLIC_URL="http://127.0.0.1:$port"
"$tmp/venv/bin/torrenthub" doctor || true
"$tmp/venv/bin/torrenthub" serve --host 127.0.0.1 --port "$port" >"$tmp/serve.log" 2>&1 &
pid=$!
for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$port/healthz"; echo
curl -sf "http://127.0.0.1:$port/api/thub/info"; echo
"$tmp/venv/bin/torrenthub" doctor --probe | tail -3
echo "smoke test passed"
