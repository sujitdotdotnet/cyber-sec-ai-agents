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
