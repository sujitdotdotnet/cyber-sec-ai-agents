import io
import sys
import time
import types
import zipfile
from pathlib import Path

import pytest

from secagents import sources
from secagents.sources import SourceError

BS = chr(92)  # a backslash, for Windows network paths


@pytest.fixture(autouse=True)
def fresh_cache():
    sources.clear_cache()
    yield
    sources.clear_cache()


def make_zip(files: dict[str, str | bytes], top: str = "repo-main") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(f"{top}/{name}" if top else name, content)
    return buf.getvalue()


# ---- classification ---------------------------------------------------------------------------
@pytest.mark.parametrize("spec, kind", [
    (r"C:\projects\app", "local"), ("/home/me/app", "local"), ('  "C:\\code\\app"  ', "local"),
    (BS * 2 + "server" + BS + "share" + BS + "code", "network"),
    ("https://github.com/o/r", "github"), ("https://github.com/o/r/tree/main/src", "github"),
    ("http://www.github.com/o/r.git", "github"), ("git@github.com:o/r.git", "github"), ("github.com/o/r", "github"),
    ("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", "gdrive"),
])
def test_classify(spec, kind):
    assert sources.classify(spec) == kind


@pytest.mark.parametrize("spec", ["https://example.com/o/r", "https://gitlab.com/o/r", "ftp://github.com/o/r", "   ", ""])
def test_classify_rejects_unsupported(spec):
    with pytest.raises(SourceError):
        sources.classify(spec)


# ---- GitHub URL parsing -------------------------------------------------------------------------
def test_parse_github_forms():
    assert sources.parse_github("https://github.com/o/r") == ("o", "r", [("HEAD", "")])
    assert sources.parse_github("https://github.com/o/r.git/") == ("o", "r", [("HEAD", "")])
    assert sources.parse_github("git@github.com:o/r.git") == ("o", "r", [("HEAD", "")])
    assert sources.parse_github("https://github.com/o/r/tree/main") == ("o", "r", [("main", "")])
    assert sources.parse_github("https://github.com/o/r/commits/main")[2] == [("HEAD", "")]  # other pages: default branch


def test_parse_github_tries_every_branch_folder_split():
    owner, repo, tries = sources.parse_github("https://github.com/o/r/tree/feature/x/src/app")
    assert tries == [("feature", "x/src/app"), ("feature/x", "src/app"), ("feature/x/src", "app"), ("feature/x/src/app", "")]


@pytest.mark.parametrize("spec", ["https://github.com/onlyowner", "https://github.com/o/r/blob/main/a.py", "https://github.com/bad name/r",
                                  "https://github.com/o/r%20x"])
def test_parse_github_rejects_bad_links(spec):
    with pytest.raises(SourceError):
        sources.parse_github(spec)


# ---- unpacking untrusted archives -----------------------------------------------------------------
def test_safe_extract_strips_the_top_folder(tmp_path):
    n = sources.safe_extract(make_zip({"app.py": "x = 1", "pkg/mod.py": "y = 2"}), tmp_path)
    assert n == 2 and (tmp_path / "app.py").read_text() == "x = 1" and (tmp_path / "pkg" / "mod.py").exists()


def test_safe_extract_blocks_zip_slip(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("repo/ok.py", "ok")
        z.writestr("repo/../../evil.txt", "pwned")
        z.writestr("repo/sub/../../../evil2.txt", "pwned")
        z.writestr("/abs/evil3.txt", "pwned")
        z.writestr("C:/evil4.txt", "pwned")
    sources.safe_extract(buf.getvalue(), dest)
    assert [p.name for p in dest.rglob("*") if p.is_file()] == ["ok.py"]  # only the honest entry was written
    assert not list(tmp_path.rglob("evil*")) and not (tmp_path.parent / "evil.txt").exists()  # nothing left dest


def test_safe_extract_skips_symlinks(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        link = zipfile.ZipInfo("repo/link")
        link.external_attr = (0o120777 << 16)  # a symlink entry
        z.writestr(link, "/etc/passwd")
        z.writestr("repo/real.py", "x")
    sources.safe_extract(buf.getvalue(), tmp_path)
    assert (tmp_path / "real.py").exists() and not (tmp_path / "link").exists()


def test_safe_extract_limits(tmp_path):
    with pytest.raises(SourceError, match="files"):
        sources.safe_extract(make_zip({f"f{i}.py": "x" for i in range(5)}), tmp_path / "a", max_files=3)
    with pytest.raises(SourceError, match="MB"):
        sources.safe_extract(make_zip({"big.py": "x" * 5000}), tmp_path / "b", max_bytes=1000)
    with pytest.raises(SourceError, match="valid archive"):
        sources.safe_extract(b"this is not a zip", tmp_path / "c")


# ---- downloading from GitHub: hosts and tokens ---------------------------------------------------------
class FakeResponse:
    def __init__(self, status=200, headers=None, body=b""):
        self.status_code, self.headers, self._body = status, headers or {}, body

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]

    def close(self):
        pass


def fake_get(routes: dict[str, FakeResponse], seen: list):
    def get(url, headers=None, **kw):
        seen.append((url, dict(headers or {}), kw.get("allow_redirects")))
        return routes[url]
    return get


@pytest.mark.parametrize("url, ok", [
    ("https://github.com/o/r/archive/HEAD.zip", True), ("https://codeload.github.com/o/r/zip/HEAD", True),
    ("https://api.github.com/repos/o/r/zipball/main", True), ("https://objects.githubusercontent.com/x", True),
    ("https://evilgithub.com/x", False), ("https://github.com.evil.com/x", False), ("http://github.com/x", False),
    ("https://example.com/x", False), ("https://githubusercontent.com.attacker.io/x", False),
])
def test_only_github_hosts_are_followed(url, ok):
    assert sources._allowed_redirect(url) is ok


def test_token_only_goes_to_the_api_host(monkeypatch):
    import requests

    seen: list = []
    zipped = make_zip({"a.py": "x"})
    routes = {
        "https://api.github.com/repos/o/r/zipball/main": FakeResponse(302, {"Location": "https://codeload.github.com/o/r/legacy.zip/main?token=abc"}),
        "https://codeload.github.com/o/r/legacy.zip/main?token=abc": FakeResponse(200, body=zipped),
    }
    monkeypatch.setattr(requests, "get", fake_get(routes, seen))
    assert sources._download("https://api.github.com/repos/o/r/zipball/main", token="ghp_secret") == zipped
    api_call, codeload_call = seen
    assert api_call[1]["Authorization"] == "Bearer ghp_secret"
    assert "Authorization" not in codeload_call[1]  # dropped when the host changes
    assert all(call[2] is False for call in seen)  # redirects are handled by hand, never automatically


def test_redirect_away_from_github_is_refused(monkeypatch):
    import requests

    routes = {"https://github.com/o/r/archive/HEAD.zip": FakeResponse(302, {"Location": "https://evil.example/payload.zip"})}
    monkeypatch.setattr(requests, "get", fake_get(routes, []))
    with pytest.raises(SourceError, match="redirect away from GitHub"):
        sources._download("https://github.com/o/r/archive/HEAD.zip")


def test_download_status_handling(monkeypatch):
    import requests

    url = "https://github.com/o/r/archive/HEAD.zip"
    for status, expect in ((404, None),):
        monkeypatch.setattr(requests, "get", fake_get({url: FakeResponse(status)}, []))
        assert sources._download(url) is expect
    monkeypatch.setattr(requests, "get", fake_get({url: FakeResponse(403, {"X-RateLimit-Remaining": "0"})}, []))
    with pytest.raises(SourceError, match="rate limit"):
        sources._download(url)
    monkeypatch.setattr(requests, "get", fake_get({url: FakeResponse(403)}, []))
    with pytest.raises(SourceError, match="private"):
        sources._download(url)
    monkeypatch.setattr(requests, "get", fake_get({url: FakeResponse(200, body=b"x" * 5000)}, []))
    monkeypatch.setattr(sources, "MAX_DOWNLOAD_BYTES", 1000)
    with pytest.raises(SourceError, match="larger than"):
        sources._download(url)


# ---- fetch_github: branch / folder resolution ------------------------------------------------------------
def test_fetch_github_finds_the_branch_and_the_subfolder(tmp_path, monkeypatch):
    tried = []
    zipped = make_zip({"src/app/main.py": "x = 1", "README.md": "hi"})

    def fake_download(url, token=""):
        tried.append(url)
        return zipped if url.endswith("/feature/x.zip") else None

    monkeypatch.setattr(sources, "_download", fake_download)
    res = sources.fetch_github("https://github.com/o/r/tree/feature/x/src/app", "", tmp_path)
    assert res.path == tmp_path / "src" / "app" and (res.path / "main.py").exists() and res.remote
    assert "o/r @ feature/x" in res.label and tried[0].endswith("/feature.zip")  # the shorter split was tried first


def test_fetch_github_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "_download", lambda url, token="": None)
    with pytest.raises(SourceError, match="not found"):
        sources.fetch_github("https://github.com/o/r", "", tmp_path / "a")
    monkeypatch.setattr(sources, "_download", lambda url, token="": make_zip({"a.py": "x"}))
    with pytest.raises(SourceError, match="does not exist"):
        sources.fetch_github("https://github.com/o/r/tree/main/nope", "", tmp_path / "b")


def test_a_token_switches_to_the_api_endpoint(tmp_path, monkeypatch):
    urls = []
    monkeypatch.setattr(sources, "_download", lambda url, token="": (urls.append((url, token)), make_zip({"a.py": "x"}))[1])
    sources.fetch_github("https://github.com/o/r", "ghp_x", tmp_path / "a")
    sources.fetch_github("https://github.com/o/r", "", tmp_path / "b")
    assert urls[0] == ("https://api.github.com/repos/o/r/zipball/HEAD", "ghp_x")
    assert urls[1] == ("https://github.com/o/r/archive/HEAD.zip", "")


# ---- resolve(): local / network paths and caching ----------------------------------------------------------
def test_resolve_local_folder(tmp_path):
    r = sources.resolve(f'  "{tmp_path}"  ')
    assert r.path == tmp_path and r.kind == "local" and not r.remote
    with pytest.raises(SourceError, match="Not a folder"):
        sources.resolve(str(tmp_path / "missing"))


def test_network_paths_need_windows(monkeypatch):
    monkeypatch.setattr(sources.os, "name", "posix")
    with pytest.raises(SourceError, match="only work when the dashboard runs on Windows"):
        sources.resolve(BS * 2 + "server" + BS + "share")


def test_unreachable_share_times_out_instead_of_hanging(monkeypatch):
    monkeypatch.setattr(Path, "is_dir", lambda self: time.sleep(2) or True)
    monkeypatch.setattr(sources, "PATH_CHECK_TIMEOUT", 0.2)
    started = time.time()
    with pytest.raises(SourceError, match="Timed out"):
        sources.resolve(BS * 2 + "10.255.255.1" + BS + "share") if sources.os.name == "nt" else sources.resolve_local("/mnt/x", "local")
    assert time.time() - started < 1.5


def test_remote_sources_are_cached_per_link_and_token(tmp_path, monkeypatch):
    calls = []

    def fake_fetch(spec, token, dest):
        calls.append((spec, token))
        (dest / "a.py").write_text("x")
        return sources.Resolved(dest, "github", "fake", remote=True)

    monkeypatch.setattr(sources, "fetch_github", fake_fetch)
    a = sources.resolve("https://github.com/o/r")
    b = sources.resolve("https://github.com/o/r")
    assert a is b and len(calls) == 1  # the second call is served from the cache
    sources.resolve("https://github.com/o/r", "tok")
    assert len(calls) == 2  # a different token is a different entry: private content is not shared
    sources.resolve("https://github.com/o/other")
    assert len(calls) == 3


def test_expired_cache_entries_are_fetched_again(monkeypatch):
    calls = []

    def fake_fetch(spec, token, dest):
        calls.append(1)
        return sources.Resolved(dest, "github", "fake", remote=True)

    monkeypatch.setattr(sources, "fetch_github", fake_fetch)
    sources.resolve("https://github.com/o/r")
    monkeypatch.setattr(sources.time, "time", lambda real=time.time: real() + sources.CACHE_TTL + 5)
    sources.resolve("https://github.com/o/r")
    assert len(calls) == 2


def test_failed_fetch_leaves_no_temp_folder_behind(monkeypatch):
    def boom(spec, token, dest):
        (dest / "partial.py").write_text("x")
        raise SourceError("nope")

    monkeypatch.setattr(sources, "fetch_github", boom)
    with pytest.raises(SourceError):
        sources.resolve("https://github.com/o/r")
    assert sources._temp_dirs == [] and not sources._cache


# ---- Google Drive ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("spec, fid", [
    ("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", "1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu"),
    ("https://drive.google.com/drive/u/0/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu?usp=sharing", "1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu"),
    ("https://drive.google.com/open?id=1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", "1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu"),
])
def test_parse_drive_id(spec, fid):
    assert sources.parse_drive_id(spec) == fid


def test_parse_drive_id_rejects_non_folder_links():
    with pytest.raises(SourceError):
        sources.parse_drive_id("https://drive.google.com/file/d/short/view")


def install_fake_gdown(monkeypatch, listing, contents, fail=()):
    """A stand-in for the gdown package: ``listing`` is [(path, id)], ``contents`` maps id -> text."""
    fetched = []

    def download_folder(id=None, quiet=True, use_cookies=True, skip_download=False, **kw):
        if isinstance(listing, Exception):
            raise listing
        return [types.SimpleNamespace(path=p.replace("/", BS), id=i) for p, i in listing]

    def download(id=None, output=None, quiet=True, use_cookies=True, **kw):
        fetched.append(id)
        if id in fail:
            return None
        Path(output).write_text(contents[id])
        return output

    monkeypatch.setitem(sys.modules, "gdown", types.SimpleNamespace(download_folder=download_folder, download=download))
    return fetched


def test_drive_fetches_only_relevant_files_and_honours_the_gitignore(tmp_path, monkeypatch):
    listing = [("app.py", "1"), ("notes.docx", "2"), ("requirements.txt", "3"), (".gitignore", "4"), ("node_modules/lib/x.py", "5"),
               ("logs/auth.log", "6"), ("photo.png", "7"), ("src/util.py", "8")]
    contents = {"1": "x = 1", "3": "flask==2.0", "4": "node_modules/\n", "6": "log", "8": "y = 2", "2": "", "5": "bad", "7": ""}
    fetched = install_fake_gdown(monkeypatch, listing, contents)
    res = sources.fetch_gdrive("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", tmp_path)
    got = sorted(str(p.relative_to(tmp_path)).replace(BS, "/") for p in tmp_path.rglob("*") if p.is_file())
    assert got == [".gitignore", "app.py", "logs/auth.log", "requirements.txt", "src/util.py"]
    assert "2" not in fetched and "7" not in fetched and "5" not in fetched  # not code, and an ignored folder: never downloaded
    assert res.remote and "5 files" in res.label and "not fetched" in res.note


def test_drive_reports_failed_downloads_and_empty_folders(tmp_path, monkeypatch):
    install_fake_gdown(monkeypatch, [("a.py", "1"), ("b.py", "2")], {"1": "x", "2": "y"}, fail={"2"})
    res = sources.fetch_gdrive("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", tmp_path / "a")
    assert "could not be downloaded" in res.note and "b.py" in res.note

    install_fake_gdown(monkeypatch, [], {})
    with pytest.raises(SourceError, match="empty"):
        sources.fetch_gdrive("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", tmp_path / "b")
    install_fake_gdown(monkeypatch, [("photo.png", "1")], {"1": ""})
    with pytest.raises(SourceError, match="None of the files"):
        sources.fetch_gdrive("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", tmp_path / "c")


def test_drive_private_folder_gives_a_helpful_message(tmp_path, monkeypatch):
    install_fake_gdown(monkeypatch, RuntimeError("Cannot retrieve the public link of the file"), {})
    with pytest.raises(SourceError, match="Anyone with the link"):
        sources.fetch_gdrive("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", tmp_path)


def test_drive_file_cap(tmp_path, monkeypatch):
    listing = [(f"m{i}.py", str(i)) for i in range(10)]
    install_fake_gdown(monkeypatch, listing, {str(i): "x" for i in range(10)})
    monkeypatch.setattr(sources, "DRIVE_MAX_FILES", 4)
    res = sources.fetch_gdrive("https://drive.google.com/drive/folders/1PE_YAPbtxdwoa6iZTrEucRNgomS3-BLu", tmp_path)
    assert sum(1 for p in tmp_path.rglob("*.py")) == 4 and "first 4" in res.note
