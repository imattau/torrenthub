"""`git-remote-thub`: plain git against a torrenthub (HOSTING.md, stage H3).

    git remote add hub thub://hub.example/you/model            # https
    git remote add hub thub::http://127.0.0.1:8080/you/model   # any other scheme, after thub::
    git push hub main                                          # signs with your key and publishes
    git -c thub.signer=<key> clone thub://hub.example/you/model

A git remote helper speaks a small line protocol on stdin and stdout (gitremote-helpers(7)); this
one has the `list`, `fetch` and `push` commands.

*Push* is `torrenthub publish --git` (publisher.py) driven by git: for each branch pushed it signs a
version 3 manifest for that commit with your key (`thub.keyfile`, `remote.<name>.thubkeyfile`, or
THUB_KEY_FILE / THUB_SIGNING_KEY), sends the objects the hub lacks and seeds the big files to it.
`git push --force` becomes `force: true` in the manifest, which a hub must also allow.

*Fetch* trusts the hub for nothing. The list of branches comes only from signed manifests, and only
from the keys you pinned (`?signer=` in the URL, `thub.signer`, or THUB_SIGNERS). The hub hands over
a pack; the helper checks that every commit it was asked for is exactly the one a valid manifest
signs for that branch, and that the file table derived from the commit's own tree is the table the
manifest signs. Big files are not fetched here: they arrive as pointers, and the filter in
pointers.py (or `torrenthub pull-files`) gets the bytes and checks their sha256.

Anything that goes wrong is reported to git as an error on stderr. The helper never writes anything
but protocol to stdout.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from . import gitrepo
from .manifest import ManifestInvalid, verify_manifest, with_table

REPO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
OPTIONS_OK = {"verbosity", "progress"}


class RemoteError(Exception):
    pass


def parse_url(url: str) -> tuple[str, str, list[str]]:
    """(hub base URL, owner/name, signer keys named in the URL)."""
    u = urlsplit("https://" + url[len("thub://"):] if url.startswith("thub://") else url)
    if u.scheme not in ("http", "https") or not u.netloc:
        raise ValueError(f"not a thub URL: {url!r} (use thub://host/owner/name, or thub::http://host/owner/name)")
    repo = u.path.strip("/").removesuffix(".git")
    if not REPO_NAME.fullmatch(repo):
        raise ValueError(f"the URL path must be owner/name, not {u.path!r}")
    from .signing import parse_pubkey

    signers = [parse_pubkey(k) for k in parse_qs(u.query).get("signer", [])]
    return f"{u.scheme}://{u.netloc}", repo, signers


def _git(args, **kw) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True, **kw)
    return r.stdout.strip() if r.returncode == 0 else ""


def _git_all(key: str) -> list[str]:
    return [v for v in _git(["config", "--get-all", key]).splitlines() if v]


class Helper:
    def __init__(self, remote: str, url: str, out=None, err=None):
        self.remote = remote
        self.hub, self.repo, url_signers = parse_url(url)
        from .signing import parse_pubkey

        self.signers = set(url_signers)
        self.signers |= {parse_pubkey(k) for k in _git_all("thub.signer")}
        self.signers |= {parse_pubkey(k) for k in os.environ.get("THUB_SIGNERS", "").replace(",", " ").split() if k}
        self.out = out or sys.stdout
        self.err = err or sys.stderr
        gd = os.environ.get("GIT_DIR") or _git(["rev-parse", "--git-dir"])
        self.git_dir = Path(gd).resolve() if gd else None
        self.verbosity = 1
        self._signed: dict | None = None

    def say(self, s: str = "") -> None:
        self.out.write(s + "\n")

    def log(self, s: str) -> None:
        print(f"thub: {s}", file=self.err, flush=True)

    # ------------------------------------------------------------------ the loop
    def serve(self, inp) -> int:
        batch: list[str] = []
        kind = ""
        for raw in inp:
            line = raw.rstrip("\n")
            if kind:  # collecting a batch of fetch or push lines, ended by a blank line
                if line:
                    batch.append(line)
                    continue
                try:
                    (self.do_fetch if kind == "fetch" else self.do_push)(batch)
                except (RemoteError, gitrepo.GitError, httpx.HTTPError, ManifestInvalid, ValueError) as e:
                    self.log(f"error: {e}")
                    if kind == "push":  # the batch was lost: tell git each ref failed
                        for spec in batch:
                            self.say(f'error {spec.split(" ", 1)[1].split(":")[-1]} "{_oneline(e)}"')
                    else:
                        self.out.flush()
                        return 1
                self.say()
                self.out.flush()
                kind, batch = "", []
                continue
            if line == "capabilities":
                for c in ("fetch", "push", "option"):
                    self.say(c)
                self.say()
            elif line.startswith("list"):
                try:
                    self.do_list(for_push="for-push" in line)
                except (RemoteError, httpx.HTTPError, ManifestInvalid, ValueError) as e:
                    self.log(f"error: {e}")
                    self.out.flush()
                    return 1
            elif line.startswith("option "):
                name = line.split()[1]
                if name == "verbosity":
                    self.verbosity = int(line.split()[2])
                self.say("ok" if name in OPTIONS_OK else "unsupported")
            elif line.startswith("fetch "):
                kind, batch = "fetch", [line]
                continue
            elif line.startswith("push "):
                kind, batch = "push", [line]
                continue
            elif line == "":
                self.out.flush()
                return 0
            else:
                self.say("unsupported")
            self.out.flush()
        return 0

    # ------------------------------------------------------------------ list
    def hub_get(self, path: str) -> httpx.Response:
        r = httpx.get(self.hub + path, timeout=30, follow_redirects=True)
        return r

    def signed_refs(self) -> dict:
        """branch -> (commit, Manifest), from valid manifests by pinned signers; the newest wins."""
        if self._signed is not None:
            return self._signed
        if not self.signers:
            raise RemoteError("no signer is pinned: the hub is not trusted to say what a branch holds. Pin the owner's key with "
                              "`git -c thub.signer=<key> ...`, `?signer=<key>` on the URL, `git config thub.signer <key>` or THUB_SIGNERS")
        r = self.hub_get(f"/api/thub/manifests/{self.repo}")
        if r.status_code != 200:
            raise RemoteError(f"the hub has no manifests for {self.repo} ({r.status_code})")
        best: dict = {}
        events = r.json().get("events", [])
        for ev in events:
            try:
                m = verify_manifest(ev, self.signers, self.repo)
                if m.needs_table:
                    t = self.hub_get(f"/blobs/{m.files_x}")
                    if t.status_code != 200:
                        continue
                    m = with_table(m, t.content)
            except ManifestInvalid:
                continue
            if m.git is None or m.expired():
                continue
            for ref in m.refs:
                if not gitrepo.valid_ref(ref):
                    continue
                rank = (m.seq, m.created_at, m.id)
                if ref not in best or rank > best[ref][0]:
                    best[ref] = (rank, m)
        if events and not best:
            raise RemoteError(f"the hub holds {len(events)} manifest(s) for {self.repo} and none is a valid git backed one signed by a pinned key")
        self._signed = {ref: (m.commit, m) for ref, (_, m) in best.items()}
        return self._signed

    def do_list(self, for_push: bool) -> None:
        if for_push and not self.signers:  # pushing: the hub's own word is enough to compare with, it checks again itself
            r = self.hub_get(f"/api/thub/git/{self.repo}/refs")
            refs = r.json().get("refs", {}) if r.status_code == 200 else {}
            pairs = {b: c for b, c in refs.items()}
        else:
            pairs = {b: c for b, (c, _) in self.signed_refs().items()}
        for b, c in sorted(pairs.items()):
            self.say(f"{c} refs/heads/{b}")
        if pairs and not for_push:
            head = "main" if "main" in pairs else sorted(pairs)[0]
            self.say(f"@refs/heads/{head} HEAD")
        self.say()

    # ------------------------------------------------------------------ fetch
    def do_fetch(self, lines: list[str]) -> None:
        signed = self.signed_refs()
        wants = [(l.split()[1], l.split()[2]) for l in lines]
        if self.git_dir is None:
            raise RemoteError("not inside a git repository")
        missing = []
        for sha, name in wants:
            branch = name.removeprefix("refs/heads/")
            if branch not in signed or signed[branch][0] != sha:
                raise RemoteError(f"{name} at {sha[:12]} is not what a valid manifest signs; refusing it")
            if not gitrepo.run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=self.git_dir, ok=(0, 1, 128))[0] == 0:
                missing.append(sha)
        haves = [h for h in _git(["for-each-ref", "--format=%(objectname)"], cwd=self.git_dir).split() if gitrepo.SHA40.fullmatch(h)][:64]
        for sha in dict.fromkeys(missing):
            if self.verbosity:
                self.log(f"fetching {sha[:12]}")
            r = httpx.post(f"{self.hub}/api/thub/git/{self.repo}/pack", json={"want": sha, "have": haves}, timeout=600)
            if r.status_code != 200:
                raise RemoteError(f"the hub would not send {sha[:12]} ({r.status_code} {r.headers.get('x-error-code', '')})")
            gitrepo.run_git(["index-pack", "--stdin", "--fix-thin", "--strict"], cwd=self.git_dir, stdin=r.content, timeout=600.0, fsize=1 << 33)
        for sha, name in wants:
            m = signed[name.removeprefix("refs/heads/")][1]
            d = gitrepo.derive(self.git_dir, sha, blob_max=64 << 20, small_total=256 << 20, max_files=100_000, sandbox=True)
            if d.rows != tuple(m.rows) or d.tree != m.git["tree"]:
                raise RemoteError(f"{name}: the commit the hub sent does not give the file table the manifest signs; refusing it")

    # ------------------------------------------------------------------ push
    def secret(self) -> bytes:
        from .signing import parse_secret

        path = _git(["config", "--get", f"remote.{self.remote}.thubkeyfile"]) or _git(["config", "--get", "thub.keyfile"]) or os.environ.get("THUB_KEY_FILE", "")
        raw = Path(path).expanduser().read_text() if path else os.environ.get("THUB_SIGNING_KEY", "")
        if not raw.strip():
            raise RemoteError("no signing key: set `git config thub.keyfile <path>` (or remote.<name>.thubkeyfile), THUB_KEY_FILE or THUB_SIGNING_KEY")
        return parse_secret(raw)

    def do_push(self, lines: list[str]) -> None:
        secret = self.secret()
        for line in lines:
            spec = line.split(" ", 1)[1]
            force = spec.startswith("+")
            src, _, dst = spec.lstrip("+").partition(":")
            if not dst.startswith("refs/heads/") or not src:
                self.say(f'error {dst or spec} "only branches can be pushed to a hub, and not deleted"')
                continue
            branch = dst.removeprefix("refs/heads/")
            try:
                sha = asyncio.run(self.push_one(secret, src, branch, force))
                self.say(f"ok {dst}")
                if self.verbosity:
                    self.log(f"{branch} is now {sha[:12]} on {self.hub}")
            except (RuntimeError, ValueError, gitrepo.GitError, httpx.HTTPError) as e:
                self.say(f'error {dst} "{_oneline(e)}"')

    async def push_one(self, secret: bytes, src: str, branch: str, force: bool) -> str:
        from .publisher import hub_heads, next_seq, prepare_git, publish

        top = _git(["rev-parse", "--show-toplevel"]) or str(self.git_dir)
        with tempfile.TemporaryDirectory(prefix="thub-push-") as stage:
            async with httpx.AsyncClient(timeout=30) as client:
                seq = await next_seq(client, self.hub, self.repo, branch)
                have = await hub_heads(client, self.hub, self.repo)
            pub = await asyncio.to_thread(prepare_git, secret, self.repo, Path(top), Path(stage), rev=src, refs=(branch,), seq=seq,
                                          have=have, force=force)
            swarm = None
            if pub.torrents:
                from .swarm import LibtorrentSwarm

                swarm = LibtorrentSwarm(0, dht=False)
            self.log(f"publishing {pub.commit[:12]} as seq {seq}: {len(pub.torrents)} big file(s) by torrent")
            try:
                await publish(self.hub, pub, swarm, timeout=3600.0)
            finally:
                if swarm is not None:
                    await swarm.close()
        return pub.commit


def _oneline(e) -> str:
    return " ".join(str(e).split()).replace('"', "'")[:300]


def main(argv=None) -> int:
    argv = sys.argv if argv is None else argv
    if len(argv) < 3:
        print("usage: git-remote-thub <remote> <url>", file=sys.stderr)
        return 2
    if os.environ.get("GIT_DIR"):
        os.environ["GIT_DIR"] = str(Path(os.environ["GIT_DIR"]).resolve())  # git gives a path relative to where it ran; our commands run from elsewhere
    try:
        helper = Helper(argv[1], argv[2])
    except ValueError as e:
        print(f"thub: {e}", file=sys.stderr)
        return 2
    return helper.serve(sys.stdin)


if __name__ == "__main__":
    sys.exit(main())
