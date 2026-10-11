"""Turn "where the code lives" into a local folder the scanners can read.

Accepted inputs (one text box in the dashboard):

* a local folder                      ``C:\\projects\\my-app``
* a Windows network share (UNC path)  ``\\\\server\\share\\folder``
* a GitHub repository or folder URL   ``https://github.com/owner/repo`` or ``.../tree/<ref>/<subfolder>``
* a public Google Drive folder link   ``https://drive.google.com/drive/folders/<id>``

Remote sources are downloaded into a temp folder and cached for a few minutes, so reruns of the dashboard do not
download again. Everything fetched is untrusted: archives are unpacked with path checks and size / file-count
limits (no zip-slip, no zip bombs, no symlinks) and only GitHub and Google hosts are ever contacted.
"""

from __future__ import annotations

import atexit
import hashlib
import io
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, unquote, urlparse

CACHE_TTL = 15 * 60  # seconds a downloaded copy is reused
MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024  # GitHub archive
MAX_UNPACKED_BYTES = 400 * 1024 * 1024
MAX_FILES = 20_000
DRIVE_MAX_FILES = 300  # relevant files fetched from one Drive folder
DRIVE_MAX_BYTES = 100 * 1024 * 1024
PATH_CHECK_TIMEOUT = 8  # seconds to wait for a network share before giving up
HTTP_TIMEOUT = 40
GITHUB_HOSTS = ("github.com", "www.github.com")
GITHUB_REDIRECT_DOMAINS = ("github.com", "githubusercontent.com")  # exact domain or a subdomain of it
# what the scanners read (kept in step with repo_scan): code and config, logs, dependency / image files, ignore files
RELEVANT_SUFFIXES = {".py", ".env", ".yaml", ".yml", ".json", ".cfg", ".ini", ".log"}
RELEVANT_NAMES = {".gitignore", ".ignore"}


class SourceError(Exception):
    """A problem with the folder / URL the user entered; the message is written for them."""


@dataclass
class Resolved:
    path: Path  # a local folder
    kind: str  # local | network | github | gdrive
    label: str  # short description for the UI
    note: str = ""  # something worth telling the user (skipped files, truncation, ...)
    remote: bool = False  # a downloaded snapshot: it does not change, so Live scan cannot follow it


# ---------------------------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------------------------
def clean_spec(spec: str) -> str:
    return spec.strip().strip('"').strip("'").strip()


def classify(spec: str) -> str:
    """local | network | github | gdrive. Raises SourceError for URLs we do not handle."""
    s = clean_spec(spec)
    if not s:
        raise SourceError("Enter a folder path or a link.")
    if re.match(r"^(git@github\.com:|github\.com/)", s, re.I):
        return "github"
    if re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        parsed = urlparse(s)
        host = (parsed.hostname or "").lower()
        if parsed.scheme.lower() not in ("http", "https"):
            raise SourceError(f"Only http(s) links are supported, not {parsed.scheme}://.")
        if host in GITHUB_HOSTS:
            return "github"
        if host == "drive.google.com":
            return "gdrive"
        raise SourceError(f"Links to {host or 'that site'} are not supported. Use a GitHub link, a public Google Drive "
                          "folder link, a network path (\\\\server\\share\\folder) or a local folder.")
    if s.startswith("\\\\") or (s.startswith("//") and os.name == "nt"):
        return "network"
    return "local"


# ---------------------------------------------------------------------------------------------
# local folders and network shares
# ---------------------------------------------------------------------------------------------
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="path-check")


def _is_dir_within(path: str, timeout: float) -> bool:
    """is_dir() with a time limit: an unreachable share can otherwise block for the OS network timeout."""
    future = _pool.submit(lambda: Path(path).is_dir())
    try:
        return future.result(timeout=timeout)
    except FutureTimeout as exc:
        raise SourceError(f"Timed out after {timeout:.0f}s reaching {path}. Check that the machine / share is online "
                          "and that you are signed in to it.") from exc
    except OSError as exc:
        raise SourceError(f"Cannot open {path}: {exc.strerror or exc}") from exc


def resolve_local(spec: str, kind: str) -> Resolved:
    s = clean_spec(spec)
    if kind == "network" and os.name != "nt":
        raise SourceError("Windows network paths (\\\\server\\share) only work when the dashboard runs on Windows. On this "
                          "machine, mount the share first and enter the folder it is mounted at.")
    path = os.path.expanduser(s)
    if not _is_dir_within(path, PATH_CHECK_TIMEOUT):
        raise SourceError(f"Not a folder (or not reachable): {s}")
    return Resolved(Path(path), kind, ("Network share " if kind == "network" else "Folder ") + s)


# ---------------------------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------------------------
_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def parse_github(spec: str) -> tuple[str, str, list[tuple[str, str]]]:
    """Returns (owner, repo, [(ref, subfolder), ...]) in the order to try.

    A branch name may contain slashes, so ``tree/feature/x/src`` could be ref ``feature`` + folder ``x/src`` or ref
    ``feature/x`` + folder ``src``; every split is offered and the first one GitHub knows wins.
    """
    s = clean_spec(spec)
    m = re.match(r"^git@github\.com:(?P<o>[^/]+)/(?P<r>.+?)(?:\.git)?/?$", s, re.I)
    if m:
        owner, repo, rest = m["o"], m["r"], []
    else:
        if not re.match(r"^[a-z]+://", s, re.I):
            s = "https://" + s
        parts = [unquote(p) for p in urlparse(s).path.split("/") if p]
        if len(parts) < 2:
            raise SourceError("That GitHub link needs an owner and a repository, e.g. https://github.com/owner/repo")
        owner, repo, rest = parts[0], parts[1], parts[2:]
        repo = re.sub(r"\.git$", "", repo)
    if not (_NAME.match(owner) and _NAME.match(repo)):
        raise SourceError("That does not look like a valid GitHub repository link.")
    if not rest:
        return owner, repo, [("HEAD", "")]
    if rest[0] == "tree" and len(rest) > 1:
        tail = rest[1:]
        return owner, repo, [("/".join(tail[:i]), "/".join(tail[i:])) for i in range(1, min(len(tail), 4) + 1)]
    if rest[0] == "blob":
        raise SourceError("That link points at a single file. Link the repository or a folder (…/tree/<branch>/<folder>).")
    return owner, repo, [("HEAD", "")]  # /commits, /issues, ... : fall back to the default branch


def _allowed_redirect(url: str) -> bool:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    return p.scheme == "https" and any(host == d or host.endswith("." + d) for d in GITHUB_REDIRECT_DOMAINS)


def _download(url: str, token: str = "") -> bytes | None:
    """GET a GitHub archive. Returns None for 404; follows redirects only to GitHub hosts and drops the token on the way."""
    import requests

    headers = {"User-Agent": "secagents", "Accept": "application/vnd.github+json" if "api.github.com" in url else "*/*"}
    for _ in range(6):
        if not _allowed_redirect(url):
            raise SourceError("Refusing to follow a redirect away from GitHub.")
        h = dict(headers)
        if token and (urlparse(url).hostname or "") == "api.github.com":
            h["Authorization"] = f"Bearer {token}"  # only the API host ever sees the token
        try:
            resp = requests.get(url, headers=h, stream=True, allow_redirects=False, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            raise SourceError(f"Could not reach GitHub: {exc.__class__.__name__}. Check the network connection.") from exc
        if resp.status_code in (301, 302, 303, 307, 308):
            url = requests.compat.urljoin(url, resp.headers.get("Location", ""))
            resp.close()
            continue
        if resp.status_code == 404:
            return None
        if resp.status_code in (401, 403):
            hint = "Add a GitHub token for private repositories." if not token else "The token cannot read this repository."
            if resp.headers.get("X-RateLimit-Remaining") == "0":
                hint = "GitHub's anonymous rate limit is used up; add a GitHub token or try again later."
            raise SourceError(f"GitHub refused access ({resp.status_code}). {hint}")
        if resp.status_code != 200:
            raise SourceError(f"GitHub answered HTTP {resp.status_code}.")
        buf, size = io.BytesIO(), 0
        for chunk in resp.iter_content(1 << 16):
            size += len(chunk)
            if size > MAX_DOWNLOAD_BYTES:
                raise SourceError(f"The repository archive is larger than {MAX_DOWNLOAD_BYTES // 2**20} MB. Link a sub-folder instead "
                                  "(…/tree/<branch>/<folder>).")
            buf.write(chunk)
        return buf.getvalue()
    raise SourceError("Too many redirects from GitHub.")


def safe_extract(data: bytes, dest: Path, *, max_files: int = MAX_FILES, max_bytes: int = MAX_UNPACKED_BYTES) -> int:
    """Unpack a zip archive into ``dest`` without trusting it. Returns the number of files written.

    The archive's single top-level folder is removed. Entries that would leave ``dest`` ('..', absolute paths),
    symlinks and device files are skipped, and the declared sizes are checked before anything is written.
    """
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SourceError("GitHub did not return a valid archive.") from exc
    with z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if len(infos) > max_files:
            raise SourceError(f"The archive has {len(infos):,} files; the limit is {max_files:,}. Link a sub-folder instead.")
        if sum(i.file_size for i in infos) > max_bytes:
            raise SourceError(f"The archive unpacks to more than {max_bytes // 2**20} MB. Link a sub-folder instead.")
        tops = {PurePosixPath(i.filename).parts[0] for i in infos if PurePosixPath(i.filename).parts}
        strip = 1 if len(tops) == 1 else 0
        root, written = dest.resolve(), 0
        for info in infos:
            mode = (info.external_attr >> 16) & 0o170000
            if mode and mode not in (0o100000,):  # symlink, device, fifo...
                continue
            parts = PurePosixPath(info.filename.replace("\\", "/")).parts[strip:]
            if not parts or ".." in parts or PurePosixPath(info.filename).is_absolute() or parts[0].endswith(":"):
                continue
            target = (root.joinpath(*parts)).resolve()
            if root not in target.parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 16)
            written += 1
    return written


def fetch_github(spec: str, token: str, dest: Path) -> Resolved:
    owner, repo, candidates = parse_github(spec)
    token = token.strip() or os.getenv("GITHUB_TOKEN", "")
    for ref, sub in candidates:
        url = (f"https://api.github.com/repos/{owner}/{repo}/zipball/{ref}" if token
               else f"https://github.com/{owner}/{repo}/archive/{ref}.zip")
        data = _download(url, token)
        if data is None:
            continue
        files = safe_extract(data, dest)
        root = dest.joinpath(*sub.split("/")) if sub else dest
        if not root.resolve().is_relative_to(dest.resolve()) or not root.is_dir():
            raise SourceError(f"The folder '{sub}' does not exist in {owner}/{repo} at '{ref}'.")
        shown = ref if ref != "HEAD" else "default branch"
        return Resolved(root, "github", f"GitHub {owner}/{repo} @ {shown}" + (f" / {sub}" if sub else "") +
                        f" ({len(data) / 2**20:.1f} MB, {files:,} files)", remote=True)
    hint = "" if token else " If it is a private repository, add a GitHub token."
    raise SourceError(f"GitHub repository or branch not found: {owner}/{repo}.{hint}")


# ---------------------------------------------------------------------------------------------
# Google Drive (public "anyone with the link" folders)
# ---------------------------------------------------------------------------------------------
def parse_drive_id(spec: str) -> str:
    p = urlparse(clean_spec(spec))
    m = re.search(r"/folders/([A-Za-z0-9_-]{10,})", p.path)
    fid = m.group(1) if m else (parse_qs(p.query).get("id") or [""])[0]
    if not re.fullmatch(r"[A-Za-z0-9_-]{10,}", fid or ""):
        raise SourceError("That does not look like a Google Drive folder link "
                          "(https://drive.google.com/drive/folders/<id>).")
    return fid


def _is_relevant(rel: str) -> bool:
    p = PurePosixPath(rel)
    name = p.name.lower()
    return (p.suffix.lower() in RELEVANT_SUFFIXES or name in RELEVANT_NAMES
            or name.startswith("requirements") and name.endswith(".txt") or name.startswith("dockerfile"))


def fetch_gdrive(spec: str, dest: Path, extra_skip: list[str] | None = None) -> Resolved:
    folder_id = parse_drive_id(spec)
    try:
        import gdown
    except ImportError as exc:
        raise SourceError("Google Drive folders need the 'gdown' package: pip install gdown") from exc
    from .repo_scan import IgnoreRules

    try:
        items = gdown.download_folder(id=folder_id, quiet=True, use_cookies=False, skip_download=True) or []
    except Exception as exc:  # noqa: BLE001 - gdown raises plain exceptions for private / missing / throttled folders
        raise SourceError("Could not read that Drive folder. It must be shared as 'Anyone with the link' (Viewer), "
                          f"and Google may throttle repeated downloads. ({exc.__class__.__name__})") from exc
    if not items:
        raise SourceError("The Drive folder is empty, or it is not shared with 'Anyone with the link'.")

    files = [(str(PurePosixPath(i.path.replace("\\", "/"))), i.id) for i in items]
    # fetch the ignore files first, so ignored folders (node_modules, .venv ...) are never downloaded
    for rel, fid in files:
        if PurePosixPath(rel).name.lower() in RELEVANT_NAMES and "/" not in rel:
            _drive_get(fid, dest / rel)
    patterns: list[str] = []
    for name in RELEVANT_NAMES:
        f = dest / name
        if f.is_file():
            patterns += [ln for ln in f.read_text(errors="ignore").splitlines()]
    rules = IgnoreRules(patterns + list(extra_skip or []))

    def wanted(rel: str) -> bool:
        parts = PurePosixPath(rel).parts
        return (_is_relevant(rel) and ".git" not in parts
                and not any(rules.is_ignored("/".join(parts[:k]), k < len(parts)) for k in range(1, len(parts) + 1)))

    chosen = [(rel, fid) for rel, fid in files if wanted(rel) and not (dest / rel).exists()]
    skipped = len(files) - len(chosen) - sum(1 for rel, _ in files if (dest / rel).exists())
    note = ""
    if len(chosen) > DRIVE_MAX_FILES:
        note = f"Only the first {DRIVE_MAX_FILES} relevant files of {len(chosen)} were fetched. "
        chosen = chosen[:DRIVE_MAX_FILES]

    failed: list[str] = []

    def grab(entry: tuple[str, str]) -> None:
        rel, fid = entry
        if not _drive_get(fid, dest / rel):
            failed.append(rel)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(grab, chosen))
    total = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    if total > DRIVE_MAX_BYTES:
        shutil.rmtree(dest, ignore_errors=True)
        raise SourceError(f"The relevant files in that Drive folder add up to more than {DRIVE_MAX_BYTES // 2**20} MB.")
    got = sum(1 for _ in dest.rglob("*") if _.is_file())
    if failed:
        note += f"{len(failed)} file(s) could not be downloaded (Google's download quota?): {', '.join(failed[:3])}. "
    if skipped > 0:
        note += f"{skipped} file(s) of other types or in ignored folders were not fetched."
    if not got:
        raise SourceError("None of the files in that Drive folder are code, config or logs the scanners can read.")
    return Resolved(dest, "gdrive", f"Google Drive folder ({got} files fetched, {total / 2**20:.1f} MB)", note.strip(), remote=True)


def _drive_get(file_id: str, target: Path) -> bool:
    import gdown

    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        return bool(gdown.download(id=file_id, output=str(target), quiet=True, use_cookies=False))
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------------------------
# entry point with caching
# ---------------------------------------------------------------------------------------------
_cache: dict[str, tuple[float, Resolved]] = {}
_lock = threading.Lock()
_temp_dirs: list[Path] = []


def _cleanup(older_than: float = CACHE_TTL * 2) -> None:
    now = time.time()
    for key, (ts, res) in list(_cache.items()):
        if now - ts > older_than:
            _cache.pop(key, None)
    live = {str(r.path) for _, r in _cache.values()}
    for d in list(_temp_dirs):
        try:
            old = now - d.stat().st_mtime > older_than
        except OSError:
            old = True  # already gone
        if old and not any(p.startswith(str(d)) for p in live):
            shutil.rmtree(d, ignore_errors=True)
            _temp_dirs.remove(d)


@atexit.register
def _cleanup_all() -> None:
    for d in _temp_dirs:
        shutil.rmtree(d, ignore_errors=True)


def resolve(spec: str, github_token: str = "", extra_skip: list[str] | None = None) -> Resolved:
    """The local folder for ``spec``, downloading it first when it is a GitHub or Google Drive link."""
    kind = classify(spec)
    if kind in ("local", "network"):
        return resolve_local(spec, kind)
    key = f"{kind}|{clean_spec(spec)}|{hashlib.sha256(github_token.encode()).hexdigest()[:12]}"
    with _lock:  # one download at a time; a second request for the same link then hits the cache
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < CACHE_TTL and hit[1].path.exists():
            return hit[1]
        _cleanup()
        dest = Path(tempfile.mkdtemp(prefix="sa_src_"))
        _temp_dirs.append(dest)
        try:
            res = fetch_github(spec, github_token, dest) if kind == "github" else fetch_gdrive(spec, dest, extra_skip)
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            _temp_dirs.remove(dest)
            raise
        _cache[key] = (time.time(), res)
        return res


def clear_cache() -> None:
    with _lock:
        _cache.clear()
        _cleanup_all()
        _temp_dirs.clear()
