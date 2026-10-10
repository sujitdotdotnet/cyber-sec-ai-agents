from pathlib import Path

import pytest

from secagents.repo_scan import collect_repo_inputs, parse_excludes


def make_repo(root: Path) -> Path:
    files = {
        ".gitignore": "# deps\n.venv/\n*.tmp\n/build\n",
        "app/main.py": "print('hi')\n",
        "app/requirements.txt": "flask==2.0.0\n",
        "requirements.txt": "django==3.0\n",
        "Dockerfile": "FROM python:3.8\n",
        "deploy/system_config.yaml": "os: linux\n",
        "logs/auth.log": "x\n",
        ".venv/lib/evil.py": "x = 1\n",
        ".venv/vendor.log": "x\n",
        "build/out.py": "x = 1\n",
        "tests/test_a.py": "x = 1\n",
        "notes.tmp": "x\n",
        ".git/HEAD": "ref\n",
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def staged(inputs) -> set[str]:
    code = Path(inputs["code_path"])
    return {p.relative_to(code).as_posix() for p in code.rglob("*.py")}


def test_parse_excludes():
    assert parse_excludes(" tests, docs ,,build/ ") == ["tests", "docs", "build/"]


def test_gitignore_is_honoured(tmp_path):
    inputs, found = collect_repo_inputs(str(make_repo(tmp_path)))
    assert staged(inputs) == {"app/main.py", "tests/test_a.py"}  # .venv and /build skipped
    assert [Path(p).name for p in inputs["log_paths"]] == ["auth.log"]  # .venv/vendor.log skipped
    assert found["python"] == 2 and found["logs"] == 1


def test_picks_shallowest_support_files(tmp_path):
    inputs, _ = collect_repo_inputs(str(make_repo(tmp_path)))
    assert Path(inputs["requirements_path"]) == (tmp_path / "requirements.txt").resolve()
    assert Path(inputs["dockerfile_path"]).name == "Dockerfile"
    assert Path(inputs["config_path"]).name == "system_config.yaml"


def test_extra_excludes(tmp_path):
    inputs, _ = collect_repo_inputs(str(make_repo(tmp_path)), "tests, logs")
    assert staged(inputs) == {"app/main.py"}
    assert inputs["log_paths"] == []


def test_missing_folder_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        collect_repo_inputs(str(tmp_path / "nope"))


def test_secret_scan_ignores_code_that_mentions_passwords(tmp_path):
    from secagents.agents.vuln_scanner import scan_secrets

    (tmp_path / "ok.py").write_text(
        "msg = f\"PasswordAuthentication={_g(c, 'ssh.password_authentication')}\"\n"
        "password = get_password()\nconn(password=password)\n"
    )
    (tmp_path / "bad.py").write_text("DB_PASSWORD = \"hunter2hunter2\"\n")
    assert [(f["file"], f["line"]) for f in scan_secrets(tmp_path)] == [("bad.py", 1)]


def test_ignore_entries_prefill(tmp_path):
    from secagents.repo_scan import ignore_entries

    make_repo(tmp_path)
    (tmp_path / ".ignore").write_text("# c\n.venv/\ndist/\n")
    assert ignore_entries(str(tmp_path)) == [".venv/", "*.tmp", "/build", "dist/"]  # de-duplicated, no comments


def test_box_text_drives_exclusions_when_ignore_files_off(tmp_path):
    make_repo(tmp_path)
    # box still lists the ignore-file entries, so the result matches the default behaviour
    entries = ", ".join([".venv/", "*.tmp", "/build"])
    inputs, _ = collect_repo_inputs(str(tmp_path), entries, use_ignore_files=False)
    assert staged(inputs) == {"app/main.py", "tests/test_a.py"}
    # removing an entry from the box scans that folder again
    inputs, _ = collect_repo_inputs(str(tmp_path), ".venv/, *.tmp", use_ignore_files=False)
    assert "build/out.py" in staged(inputs)
