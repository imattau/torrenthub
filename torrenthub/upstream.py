"""Clients for the upstream Hugging Face compatible hub, or several of them."""

from __future__ import annotations

import asyncio
import fnmatch
import time
from contextlib import asynccontextmanager
from typing import Callable
from urllib.parse import quote, urlparse

import httpx

from .federation import ConsensusError, Disagreement, NotEnoughAnswers, choose_consensus, fingerprint
from .manifest import SHA40
from .manifest import MAX_EVENT_BYTES, MAX_EVENTS_PER_REPO, MAX_TABLE_BYTES, ManifestInvalid, verify_manifest, with_table
from .metrics import Metrics


class HubError(Exception):
    """Raised inside the gateway and mapped to an HF style error response."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class UpstreamUnavailable(HubError):
    def __init__(self, message: str = "upstream unavailable"):
        super().__init__(502, "UpstreamUnavailable", message)


class _Signers:
    """The keys allowed to sign a repo's manifests: the listed roots, and any key a root has
    delegated `publish:<repo>` to. Supports `in`, which is all verify_manifest asks of it."""

    def __init__(self, roots: set, repo_id: str, check):
        self.roots, self.scope, self.check = roots, f"publish:{repo_id}", check

    def __contains__(self, key) -> bool:
        if key in self.roots:
            return True
        return bool(self.check and isinstance(key, str) and self.check(self.roots, key, self.scope))


def token_allowed_for(base_url: str) -> bool:
    """HF_TOKEN belongs to Hugging Face. Never send it to another hub, which in agent mode
    is somebody else's server."""
    host = (urlparse(base_url).hostname or "").lower()
    return host == "huggingface.co" or host.endswith(".huggingface.co")


class Upstream:
    is_anchor = False

    def __init__(self, base_url: str, token: str | None = None, client: httpx.AsyncClient | None = None):
        self.base_url = base_url.rstrip("/")
        headers = {"User-Agent": "torrenthub/0.1", "Accept-Encoding": "identity"}
        if token and token_allowed_for(self.base_url):
            headers["Authorization"] = f"Bearer {token}"
        self.client = client or httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            follow_redirects=True,
            timeout=httpx.Timeout(60.0, connect=10.0),
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def fetch_torrent(
        self, key: str, accept: Callable[[bytes], bool] | None = None, max_bytes: int = 4 * 1024 * 1024
    ) -> bytes | None:
        """Ask the upstream hub for the torrent of a blob. None if it has none (Hugging Face
        itself does not), cannot be reached, or `accept` refuses what it sent."""
        try:
            r = await self.client.get(f"/torrents/{key}.torrent")
        except httpx.HTTPError:
            return None
        if r.status_code != 200 or len(r.content) > max_bytes:
            return None
        if accept is not None and not accept(r.content):
            return None
        return r.content

    def resolve_url(self, repo_id: str, revision: str, path: str) -> str:
        return f"{self.base_url}/{repo_id}/resolve/{revision}/{quote(path)}"

    async def fetch_manifests(self, repo_id: str) -> list[dict]:
        """Signed manifest events this hub holds for a repo. Empty if it has none, cannot be
        reached, or answers with something else. Callers verify every event themselves."""
        try:
            r = await self.client.get(f"/api/thub/manifests/{quote(repo_id, safe='/')}")
        except httpx.HTTPError:
            return []
        if r.status_code != 200 or len(r.content) > MAX_EVENT_BYTES * 4:
            return []
        try:
            events = r.json()["events"]
        except (ValueError, KeyError, TypeError):
            return []
        return [e for e in events if isinstance(e, dict)][:MAX_EVENTS_PER_REPO] if isinstance(events, list) else []

    async def fetch_table(self, sha256: str) -> bytes | None:
        """The bytes of a published file table, by hash. None if this hub does not hold it. The
        caller checks the hash; nothing here is believed."""
        try:
            r = await self.client.get(f"/blobs/{sha256}")
        except httpx.HTTPError:
            return None
        if r.status_code != 200 or len(r.content) > MAX_TABLE_BYTES:
            return None
        return r.content

    async def model_info(self, repo_id: str, revision: str) -> dict:
        url = f"/api/models/{repo_id}/revision/{quote(revision, safe='')}"
        try:
            r = await self.client.get(url, params={"blobs": "true"})
        except httpx.HTTPError as e:
            raise UpstreamUnavailable(f"{type(e).__name__}: {e}") from e
        if r.status_code == 200:
            return r.json()
        if r.status_code in (401, 403):
            # Private or gated. The prototype only mirrors public repos, so hide it.
            raise HubError(404, "RepoNotFound", f"{repo_id} is not available for mirroring")
        if r.status_code == 404:
            code = r.headers.get("x-error-code", "RepoNotFound")
            raise HubError(404, code, f"{repo_id}@{revision} not found upstream")
        raise UpstreamUnavailable(f"upstream returned {r.status_code}")

    def stream_file(self, repo_id: str, commit: str, path: str):
        """Async context manager yielding a streaming httpx response."""
        return self.client.stream("GET", f"/{repo_id}/resolve/{commit}/{quote(path)}")


# httpx buffers until it has this many bytes before yielding. Keep it small: on a slow link a big
# chunk is a long silence for the client, which gives up after ~10s without data.
STREAM_CHUNK = 64 * 1024


class _Primed:
    """A 200 streaming response whose first chunk has already been read."""

    def __init__(self, response, first, rest):
        self._response, self._first, self._rest = response, first, rest
        self.status_code = response.status_code
        self.headers = response.headers

    async def aiter_bytes(self, chunk_size: int | None = None):
        if self._first is not None:
            yield self._first
        async for chunk in self._rest:
            yield chunk


# --------------------------------------------------------------------------- several upstreams

class UpstreamSet:
    """An ordered list of upstream hubs behaving like one upstream.

    * Metadata: with quorum 1, ask in order and use the first that answers. With a larger
      quorum, ask all of them at once and require `quorum` of them to agree (see federation.py).
    * Torrents: ask in order, use the first that passes the caller's check.
    * File bytes over HTTP: try each in order until one answers 200.
    A stream that breaks part way is not resumed on another upstream: the download fails and is
    retried from the start.
    """

    def __init__(
        self,
        sources: list[Upstream],
        quorum: int = 1,
        meta_timeout: float = 15.0,
        anchor: Upstream | None = None,
        anchor_required: bool = True,
        trust: list[tuple[str, str]] | None = None,
        default_mode: str | None = None,
        manifest_max_age: float | None = None,
    ):
        self.trust = list(trust or [])
        # Longest a manifest's own timestamp may lag when a branch name is resolved (seconds).
        # None means no limit. A commit sha is content addressed and is never refused for age.
        self.manifest_max_age = manifest_max_age
        # Set by the app: (root keys, signer, scope) -> True if the signer holds a live delegation
        # chain from one of the roots for that scope. Without it only the listed keys may sign.
        self.delegation_check: Callable[[set, str, str], bool] | None = None
        self.on_manifest: Callable[[dict], object] | None = None  # set by the mirror to keep verified manifests
        self.default_mode = default_mode or ("anchor" if anchor is not None else "hub")
        if anchor is None and any(m.startswith("anchor") for _, m in self.trust):
            raise ValueError("a trust rule needs an anchor, and none is configured")
        self.anchor = anchor
        self.anchor_required = anchor_required
        if not sources:
            raise ValueError("at least one upstream is required")
        if not 1 <= quorum <= len(sources):
            raise ValueError(f"quorum {quorum} needs between 1 and {len(sources)} upstreams")
        self.sources = sources
        self.quorum = quorum
        self.meta_timeout = meta_timeout
        self.metrics: Metrics | None = None  # set by the mirror

    @property
    def base_url(self) -> str:
        return self.sources[0].base_url

    def resolve_url(self, repo_id: str, revision: str, path: str) -> str:
        return self.sources[0].resolve_url(repo_id, revision, path)

    async def aclose(self) -> None:
        everyone = list(self.sources) + ([self.anchor] if self.anchor else [])
        await asyncio.gather(*(u.aclose() for u in everyone), return_exceptions=True)

    def _note(self, u: Upstream, kind: str, result: str) -> None:  # noqa: D401
        if self.metrics:
            self.metrics.inc(
                "thub_upstream_requests_total", upstream=urlparse(u.base_url).netloc, kind=kind, result=result
            )

    # metadata ------------------------------------------------------------------------

    async def _ask(self, u: Upstream, repo_id: str, revision: str, label: str = "meta") -> tuple[str, object]:
        kind = label
        try:
            info = await asyncio.wait_for(u.model_info(repo_id, revision), self.meta_timeout)
        except HubError as e:
            self._note(u, kind, "notfound" if e.status in (404, 451) else "error")
            return ("notfound" if e.status in (404, 451) else "error"), e
        except (asyncio.TimeoutError, httpx.HTTPError) as e:
            self._note(u, kind, "error")
            return "error", e
        self._note(u, kind, "ok")
        return "ok", info

    def mode_for(self, repo_id: str) -> str:
        for glob, mode in self.trust:
            if fnmatch.fnmatchcase(repo_id, glob):
                return mode
        return self.default_mode

    async def _from_anchor(self, repo_id: str, revision: str) -> dict | None:
        """The anchor's answer, which settles what the correct hashes are. None means it could
        not be reached and `anchor_required` is off, so the caller falls back to the hubs."""
        kind, payload = await self._ask(self.anchor, repo_id, revision, label="anchor")
        if kind == "ok":
            return payload  # type: ignore[return-value]
        if kind == "notfound":
            raise payload  # type: ignore[misc]
        if self.anchor_required:
            if self.metrics:
                self.metrics.inc("thub_anchor_unavailable_total")
            raise UpstreamUnavailable(f"the anchor {self.anchor.base_url} could not be reached: {payload}")
        if self.metrics:
            self.metrics.inc("thub_anchor_skipped_total")
        return None

    async def model_info(self, repo_id: str, revision: str) -> dict:
        return (await self.model_info_ex(repo_id, revision))[0]

    async def model_info_ex(self, repo_id: str, revision: str) -> tuple[dict, str]:
        """The file table and where it came from: "anchor" (checked with the origin), "hub" (a
        hub answered where the policy allows that, with an anchor available) or "upstream" (there
        is no anchor, so the upstreams are trusted)."""
        mode = self.mode_for(repo_id)
        if mode.startswith("signed:"):
            info = await self._signed_info(repo_id, revision, set(mode[len("signed:"):].split("+")))
            self._count_source("signed")
            return info, "signed"
        if mode.startswith("anchor"):
            try:
                info = await self._from_anchor(repo_id, revision)
            except HubError as e:
                if not (mode == "anchor-or-hub" and e.status in (404, 451)):
                    raise
                anchor_404 = e  # the origin does not have it: look in the hubs, and say so
                info = await self._from_hubs(repo_id, revision, fallback_error=anchor_404)
                self._count_source("hub")
                return info, "hub"
            if info is not None:
                self._count_source("anchor")
                return info, "anchor"
            source = "hub"  # anchor unreachable and not required
        else:
            source = "hub" if self.anchor is not None else "upstream"
        info = await self._from_hubs(repo_id, revision)
        self._count_source(source)
        return info, source

    async def _signed_info(self, repo_id: str, revision: str, keys: set[str]) -> dict:
        """The file table the creator signed, taken from whichever hub can supply it.

        The hubs only say where to find things. Which commit a name means comes from the signed
        manifests (newest signed claim on a branch name wins), and a hub's table is accepted only
        if it is exactly the signed one. A hub that disagrees is skipped, not believed."""
        batches = await asyncio.gather(*(u.fetch_manifests(repo_id) for u in self.sources))
        seen: dict[str, object] = {}
        for events in batches:
            for ev in events:
                if not isinstance(ev, dict) or ev.get("id") in seen:
                    continue
                try:
                    seen[ev.get("id")] = verify_manifest(ev, _Signers(keys, repo_id, self.delegation_check), repo_id)
                except ManifestInvalid:
                    seen[ev.get("id")] = None
                    if self.metrics:
                        self.metrics.inc("thub_manifest_total", result="invalid")
        valid = [m for m in seen.values() if m is not None]
        if self.metrics and valid:
            self.metrics.inc("thub_manifest_total", len(valid), result="valid")
        if not valid:
            raise HubError(502, "NoValidManifest", f"no manifest for {repo_id} signed by a trusted key")
        pinned = bool(SHA40.match(revision or ""))
        if pinned:
            cands = [m for m in valid if m.commit == revision]
        else:
            cands = [m for m in valid if revision in m.refs]
        if not cands:
            raise HubError(404, "RevisionNotFound", f"{repo_id}@{revision} has no signed manifest")
        if not pinned:
            # A branch name is a claim about now, so it can go stale. A commit sha cannot.
            now = time.time()
            fresh = [m for m in cands if not m.expired(now)]
            if not fresh:
                raise HubError(502, "ManifestExpired", f"every signed manifest for {repo_id}@{revision} has passed its valid_until")
            cands = fresh
        # The creator's own counter decides which claim is newest, so a hub cannot win by replaying
        # an older manifest. Version 1 manifests have no counter and rank by timestamp among themselves.
        chosen = max(cands, key=lambda m: (m.seq, m.created_at, m.id))
        if not pinned and self.manifest_max_age is not None and time.time() - chosen.created_at > self.manifest_max_age:
            raise HubError(502, "ManifestStale", f"the newest signed manifest for {repo_id}@{revision} is older than {self.manifest_max_age:.0f}s")
        if chosen.needs_table:
            for u in self.sources:
                blob = await u.fetch_table(chosen.files_x)
                if blob is not None:
                    try:
                        chosen = with_table(chosen, blob)
                        break
                    except ManifestInvalid:
                        if self.metrics:
                            self.metrics.inc("thub_manifest_total", result="bad_table")
            if chosen.needs_table:
                raise UpstreamUnavailable(f"no hub could supply the file table {chosen.files_x[:12]} that {repo_id}@{chosen.commit[:12]} was signed with")
        mismatched = False
        for u in self.sources:
            kind, info = await self._ask(u, repo_id, chosen.commit)
            if kind != "ok":
                continue
            if info.get("sha") == chosen.commit and tuple(fingerprint(info)) == chosen.rows:  # type: ignore[union-attr]
                if self.on_manifest:
                    self.on_manifest(chosen.event)
                return info  # type: ignore[return-value]
            mismatched = True
            if self.metrics:
                self.metrics.inc("thub_manifest_hub_mismatch_total")
        if mismatched:
            raise HubError(502, "ManifestMismatch", f"no hub gave the file table that {repo_id}@{chosen.commit[:12]} was signed with")
        raise UpstreamUnavailable(f"no hub could supply {repo_id}@{chosen.commit[:12]}")

    def _count_source(self, source: str) -> None:
        if self.metrics:
            self.metrics.inc("thub_metadata_source_total", source=source)

    async def _from_hubs(self, repo_id: str, revision: str, fallback_error: HubError | None = None) -> dict:
        try:
            if self.quorum == 1:
                return await self._first_answer(repo_id, revision)
            return await self._agreed_answer(repo_id, revision)
        except HubError as e:
            if fallback_error is not None and e.status in (404, 451):
                raise fallback_error from e  # nobody has it
            raise

    async def _first_answer(self, repo_id: str, revision: str) -> dict:
        first_404: HubError | None = None
        for u in self.sources:
            kind, payload = await self._ask(u, repo_id, revision)
            if kind == "ok":
                return payload  # type: ignore[return-value]
            if kind == "notfound" and first_404 is None:
                first_404 = payload  # type: ignore[assignment]
        if first_404 is not None:
            raise first_404
        raise UpstreamUnavailable("no upstream could be reached")

    async def _agreed_answer(self, repo_id: str, revision: str) -> dict:
        results = await asyncio.gather(*(self._ask(u, repo_id, revision) for u in self.sources))
        oks = [(i, p) for i, (k, p) in enumerate(results) if k == "ok"]
        if not oks:
            for kind, payload in results:
                if kind == "notfound":
                    raise payload  # type: ignore[misc]
            raise UpstreamUnavailable("no upstream could be reached")
        try:
            return choose_consensus(oks, self.quorum, revision)[1]  # type: ignore[arg-type]
        except NotEnoughAnswers as e:
            raise UpstreamUnavailable(str(e)) from e
        except Disagreement as e:
            if self.metrics:
                self.metrics.inc("thub_metadata_disagreements_total")
            raise HubError(502, "UpstreamDisagreement", str(e)) from e
        except ConsensusError as e:  # pragma: no cover - subclasses above cover it
            raise UpstreamUnavailable(str(e)) from e

    # torrents ------------------------------------------------------------------------

    async def fetch_torrent(
        self, key: str, accept: Callable[[bytes], bool] | None = None, max_bytes: int = 4 * 1024 * 1024
    ) -> bytes | None:
        for u in self.sources:
            data = await u.fetch_torrent(key, accept, max_bytes)
            self._note(u, "torrent", "ok" if data is not None else "none")
            if data is not None:
                return data
        return None

    # bytes ---------------------------------------------------------------------------

    @asynccontextmanager
    async def stream_file(self, repo_id: str, commit: str, path: str):
        saw_404 = saw_other = False
        for u in self.sources:
            cm = u.stream_file(repo_id, commit, path)
            try:
                r = await cm.__aenter__()
            except httpx.HTTPError:
                self._note(u, "file", "error")
                saw_other = True
                continue
            if r.status_code == 200:
                # Read the first chunk before committing to this upstream. A hub that answers 200
                # and then breaks before sending anything is skipped like one that answered 5xx.
                it = r.aiter_bytes(STREAM_CHUNK)
                try:
                    first = await it.__anext__()
                except StopAsyncIteration:
                    first = None  # an empty file is a legitimate 200
                except httpx.HTTPError:
                    await cm.__aexit__(None, None, None)
                    self._note(u, "file", "error")
                    saw_other = True
                    continue
                self._note(u, "file", "ok")
                try:
                    yield _Primed(r, first, it)
                finally:
                    await cm.__aexit__(None, None, None)
                return
            await cm.__aexit__(None, None, None)
            if r.status_code == 404:
                saw_404 = True
                self._note(u, "file", "notfound")
            else:
                saw_other = True
                self._note(u, "file", "error")
        if saw_404 and not saw_other:
            raise HubError(404, "EntryNotFound", f"{path} not found on any upstream")
        raise UpstreamUnavailable(f"no upstream could supply {path}")


def make_upstream(settings) -> "Upstream | UpstreamSet":
    """One upstream stays a plain Upstream. Several, a quorum above 1, or an anchor that is not
    itself the only upstream, become an UpstreamSet."""
    from .config import effective_anchor

    urls = list(settings.upstreams) or [settings.upstream]
    anchor_url = effective_anchor(settings)
    if anchor_url:
        urls = [u for u in urls if u.rstrip("/") != anchor_url.rstrip("/")]
        if not urls and not getattr(settings, "trust", []):
            only = Upstream(anchor_url, settings.hf_token)  # the anchor is the only upstream
            only.is_anchor = True
            return only
        if not urls:  # trust rules need something to be a "hub": use the anchor's address for it
            urls = [anchor_url]
    trust = list(getattr(settings, "trust", []))
    sources = [Upstream(u, settings.hf_token) for u in urls]
    anchor = Upstream(anchor_url, settings.hf_token) if anchor_url else None
    if anchor is None and len(sources) == 1 and settings.quorum <= 1 and not trust:
        return sources[0]
    quorum = min(settings.quorum, len(sources)) if anchor else settings.quorum
    return UpstreamSet(sources, quorum, settings.meta_timeout, anchor, settings.anchor_required, trust,
                       manifest_max_age=getattr(settings, "manifest_max_age", None))
