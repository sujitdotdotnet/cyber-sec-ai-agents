"""Command line entry point: `python -m secagents [--out report.md] [--json results.json] [--docx|--xlsx|--pdf FILE]`."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .exporters import export
from .graph import default_inputs, stream
from .llm import get_router
from .version import app_title


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the five-agent security assessment.")
    ap.add_argument("--version", action="version", version=app_title())
    ap.add_argument("--logs", nargs="*", help="Log files (default: the demo scenario)")
    ap.add_argument("--code", help="Source directory to scan")
    ap.add_argument("--requirements", help="requirements.txt to inventory")
    ap.add_argument("--dockerfile", help="Dockerfile to lint")
    ap.add_argument("--config", help="System configuration YAML for the policy check")
    ap.add_argument("--out", default="security_report.md", help="Markdown report path")
    ap.add_argument("--json", dest="json_out", help="Also write the full results as JSON")
    for fmt, label in (("docx", "Word"), ("xlsx", "Excel"), ("pdf", "PDF")):
        ap.add_argument(f"--{fmt}", help=f"Also write the report as a {label} file")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    inputs = default_inputs()
    for key, val in (("log_paths", args.logs), ("code_path", args.code), ("requirements_path", args.requirements),
                     ("dockerfile_path", args.dockerfile), ("config_path", args.config)):
        if val:
            inputs[key] = val

    providers = get_router().available_providers()
    print(f"LLM providers: {', '.join(providers) or 'none (rule-based mode)'}")
    state: dict = {}
    for node, update in stream(inputs):
        for t in update.get("trace", []):
            print(f"[{t['ts']}] {t['agent']:<18} {t['message']}")
        state.update({k: v for k, v in update.items() if k not in ("trace", "completed")})

    Path(args.out).write_text(state.get("report_md", ""))
    print(f"\nReport written to {args.out}")
    for fmt in ("docx", "xlsx", "pdf"):
        if getattr(args, fmt):
            Path(getattr(args, fmt)).write_bytes(export(fmt, state, {}))
            print(f"{fmt.upper()} report written to {getattr(args, fmt)}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(state, indent=2, default=str))
        print(f"Results written to {args.json_out}")


if __name__ == "__main__":
    main()
