"""Daily knowledge sync and live OSV lookup, against saved samples (no network)."""

import json
import shutil
import types
from dataclasses import replace
from pathlib import Path

import pytest

from secagents import knowledge, knowledge_sync as ks, osv
from secagents.agents import threat_intel
from secagents.agents.threat_intel import merge_live, satisfies
from secagents.config import settings
from secagents.db import Db
from secagents.rag.store import KnowledgeBase


# ---- samples -----------------------------------------------------------------------------------------------------
def adv(osv_id="PYSEC-2018-28", cve="CVE-2018-18074", name="requests", ranges=None, **extra):
    return {"id": osv_id, "aliases": [cve] if cve else [], "summary": "Authorization header leak", "details": "Details.\nMore.",
            "modified": "2026-10-20T10:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "affected": [{"package": {"name": name, "ecosystem": "PyPI"},
                          "ranges": ranges if ranges is not None else [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}], **extra}


def kev_doc(n=3):
    return {"dateReleased": "2026-10-21T15:00:00Z", "catalogVersion": "2026.10.21", "vulnerabilities": [
        {"cveID": f"CVE-2021-{44228 + i}", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates."}
        for i in range(n)]}


def stix_bundle():
    def pattern(i, name, ext, sub=False, **kw):
        return {"type": "attack-pattern", "id": f"attack-pattern--{i}", "name": name, "description": "Adversaries may [guess](https://x.io) passwords.(Citation: Foo)",
                "external_references": [{"source_name": "mitre-attack", "external_id": ext}], "x_mitre_is_subtechnique": sub,
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}], **kw}

    return {"objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "20.0", "modified": "2026-10-13T00:00:00Z"},
        pattern("1", "Brute Force", "T1110"), pattern("2", "Password Guessing", "T1110.001", sub=True),
        pattern("3", "Old Thing", "T9999", revoked=True), pattern("4", "Gone", "T9998", x_mitre_deprecated=True),
        {"type": "relationship", "id": "relationship--1", "relationship_type": "subtechnique-of", "source_ref": "attack-pattern--2", "target_ref": "attack-pattern--1"},
        {"type": "course-of-action", "id": "course-of-action--1", "name": "Multi-factor Authentication",
         "external_references": [{"source_name": "mitre-attack", "external_id": "M1032"}]},
        {"type": "relationship", "id": "relationship--2", "relationship_type": "mitigates", "source_ref": "course-of-action--1", "target_ref": "attack-pattern--2"},
        {"type": "x-mitre-analytic", "id": "x-mitre-analytic--1", "description": "Watch repeated failed SSH logins.(Citation: Bar)"},
        {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--1", "name": "Password Guessing Detection", "x_mitre_analytic_refs": ["x-mitre-analytic--1"]},
        {"type": "relationship", "id": "relationship--3", "relationship_type": "detects", "source_ref": "x-mitre-detection-strategy--1", "target_ref": "attack-pattern--2"},
    ]}


@pytest.fixture(autouse=True)
def small_thresholds(monkeypatch):
    monkeypatch.setattr(ks, "MIN_KEV", 2)
    monkeypatch.setattr(ks, "MIN_ATTACK", 2)
    monkeypatch.setattr(ks, "MIN_OSV", 1)
    monkeypatch.setattr(ks, "time", types.SimpleNamespace(sleep=lambda s: None))  # no real waiting between retries (only for this module)


# ---- CVSS and advisory conversion --------------------------------------------------------------------------------------
@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_scores_match_the_official_calculator(vector, score):
    assert osv.cvss3_score(vector) == score


def test_unsupported_or_broken_vectors_give_no_score_and_fall_back_to_the_label():
    assert osv.cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert osv.cvss3_score("nonsense") is None and osv.cvss3_score("CVSS:3.1/AV:X") is None
    assert osv.score_and_severity({"database_specific": {"severity": "MODERATE"}}) == (5.5, "MEDIUM")
    assert osv.score_and_severity({"database_specific": {"severity": "CRITICAL"}}) == (9.5, "CRITICAL")
    assert osv.score_and_severity({}) == (0.0, "UNKNOWN")


def test_an_advisory_becomes_a_record_in_the_knowledge_base_shape():
    [rec] = osv.advisory_to_records(adv())
    assert (rec["id"], rec["package"], rec["ecosystem"], rec["affected"], rec["fixed"]) == ("CVE-2018-18074", "requests", "pypi", "<2.20.0", "2.20.0")
    assert (rec["cvss"], rec["severity"], rec["source"], rec["osv_id"]) == (7.5, "HIGH", "OSV", "PYSEC-2018-28")
    assert rec["title"] == "Authorization header leak" and rec["description"] == "Details. More."
    assert {"id", "package", "ecosystem", "affected", "fixed", "cvss", "severity", "title", "description"} <= set(rec)  # what doc_text needs


def test_version_ranges_become_specs_the_matcher_understands():
    two = [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.4.2"}, {"introduced": "2.0"}, {"fixed": "2.1.1"}]}]
    [rec] = osv.advisory_to_records(adv(ranges=two))
    assert rec["affected"] == ">=1.0,<1.4.2 || >=2.0,<2.1.1" and rec["fixed"] == "1.4.2, 2.1.1"
    assert satisfies("1.3.0", rec["affected"]) and satisfies("2.0.5", rec["affected"])
    assert satisfies("1.5.0", rec["affected"]) is False and satisfies("2.1.1", rec["affected"]) is False
    [last] = osv.advisory_to_records(adv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "3.0.1"}]}]))
    assert last["affected"] == "<=3.0.1"
    [open_ended] = osv.advisory_to_records(adv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "4.0"}]}]))
    assert open_ended["affected"] == ">=4.0" and open_ended["fixed"] == "no fix listed"
    listed = adv(ranges=[])
    listed["affected"][0]["versions"] = ["1.0", "1.1"]
    assert osv.advisory_to_records(listed)[0]["affected"] == "==1.0 || ==1.1"


def test_withdrawn_other_ecosystems_and_other_packages_are_skipped():
    assert osv.advisory_to_records(adv(withdrawn="2026-01-01T00:00:00Z")) == []
    npm = adv()
    npm["affected"][0]["package"]["ecosystem"] = "npm"
    assert osv.advisory_to_records(npm) == []
    assert osv.advisory_to_records(adv(), package="django") == [] and len(osv.advisory_to_records(adv(), package="Requests")) == 1
    assert osv.advisory_to_records(adv(name="Flask_Login"), package="flask-login")[0]["package"] == "flask-login"  # PEP 503 names


def test_without_a_cve_alias_the_osv_id_is_the_id():
    assert osv.advisory_to_records(adv(osv_id="GHSA-xxxx-yyyy-zzzz", cve=None))[0]["id"] == "GHSA-xxxx-yyyy-zzzz"


def test_or_specs_and_undecidable_specs():
    assert satisfies("1.0", "<2.0 || >=5.0") is True and satisfies("3.0", "<2.0 || >=5.0") is False
    assert satisfies("1.0", "banana") is None and satisfies("9.9", "<2.0 || banana") is None  # cannot be sure
    assert satisfies("1.0", "<2.0 || banana") is True  # one alternative is enough
    assert satisfies("2.19.1", "<2.20.0") is True and satisfies("2.20.0", "<2.20.0") is False


# ---- KEV and ATT&CK parsing -----------------------------------------------------------------------------------------------
def test_kev_is_parsed_sorted_and_checked_for_plausibility():
    records, info = ks.parse_kev(kev_doc(3))
    assert [r["id"] for r in records] == ["CVE-2021-44228", "CVE-2021-44229", "CVE-2021-44230"]
    assert info["count"] == 3 and info["source_date"] == "2026-10-21" and records[0]["ransomware"] == "Known"
    with pytest.raises(ks.SyncError, match="only 1 entries"):
        ks.parse_kev(kev_doc(1))
    with pytest.raises(ks.SyncError):
        ks.parse_kev({"oops": []})


def test_attack_techniques_subtechniques_mitigations_and_detections():
    records, info = ks.parse_attack(stix_bundle())
    by_id = {r["id"]: r for r in records}
    assert set(by_id) == {"T1110", "T1110.001"}  # revoked and deprecated techniques are left out
    sub = by_id["T1110.001"]
    assert sub["name"] == "Brute Force: Password Guessing" and sub["tactic"] == "Credential Access"
    assert sub["mitigation"] == "Multi-factor Authentication (M1032)"
    assert sub["detection"] == "Password Guessing Detection: Watch repeated failed SSH logins."
    assert sub["description"] == "Adversaries may guess passwords."  # citations and link markup removed
    assert info["version"] == "20.0" and info["source_date"] == "2026-10-13"
    with pytest.raises(ks.SyncError):
        ks.parse_attack({"objects": [{"type": "x-mitre-collection"}]})


def test_osv_records_get_unique_ids_and_kev_flags():
    other = adv(osv_id="PYSEC-2018-29", name="requests-oauthlib")  # the same CVE affecting a second package
    recs = ks.build_osv_records({"requests": [adv()], "requests-oauthlib": [other]}, {"CVE-2018-18074"})
    assert sorted(r["id"] for r in recs) == ["CVE-2018-18074", "CVE-2018-18074:requests-oauthlib"]
    assert all(r["kev"] for r in recs)


def test_the_watchlist_ignores_comments_blanks_and_duplicates(tmp_path):
    f = tmp_path / "w.txt"
    f.write_text("# header\nFlask\n\nrequests  # http\nflask\nPyYAML\n")
    assert ks.read_watchlist(f) == ["flask", "requests", "pyyaml"]
    assert ks.read_watchlist(tmp_path / "missing.txt") == []


STATE: dict = {}  # what the fake feeds return in the current test


# ---- the sync run ------------------------------------------------------------------------------------------------------------
@pytest.fixture
def kdir(tmp_path, monkeypatch):
    d = tmp_path / "knowledge"
    d.mkdir()
    (d / "watchlist.txt").write_text("requests\n")
    state = STATE
    state.clear()
    state.update({"kev": kev_doc(3), "attack": stix_bundle(), "osv": [adv()], "fail": set()})

    def maybe(name):
        if name in state["fail"]:
            raise ks.SyncError(f"{name} is down")

    monkeypatch.setattr(ks, "fetch_kev", lambda: (maybe("kev"), ks.parse_kev(state["kev"]))[1])
    monkeypatch.setattr(ks, "fetch_attack", lambda: (maybe("attack"), ks.parse_attack(state["attack"]))[1])
    monkeypatch.setattr(ks, "_query_package", lambda name: (maybe("osv"), state["osv"])[1])
    return d


def test_first_run_writes_every_file_and_the_metadata(kdir):
    results = ks.run(directory=kdir, log=lambda m: None)
    assert results == {"kev": "changed", "osv": "changed", "attack": "changed"}
    assert len((kdir / "kev.jsonl").read_text().splitlines()) == 3
    assert json.loads((kdir / "cves_synced.jsonl").read_text().splitlines()[0])["kev"] is False  # CVE-2018-18074 is not in this KEV sample
    assert json.loads((kdir / "attack_synced.jsonl").read_text().splitlines()[1])["id"] == "T1110.001"
    meta = json.loads((kdir / "meta.json").read_text())
    assert set(meta["sources"]) == {"cisa_kev", "osv", "mitre_attack"} and meta["updated_at"].endswith("Z")
    assert meta["sources"]["osv"]["packages"] == 1 and meta["sources"]["mitre_attack"]["version"] == "20.0"


def test_a_quiet_day_rewrites_nothing(kdir):
    ks.run(directory=kdir, log=lambda m: None)
    before = {p.name: (p.stat().st_mtime_ns, p.read_text()) for p in kdir.iterdir()}
    assert ks.run(directory=kdir, log=lambda m: None) == {"kev": "unchanged", "osv": "unchanged", "attack": "unchanged"}
    assert {p.name: (p.stat().st_mtime_ns, p.read_text()) for p in kdir.iterdir()} == before  # no file touched, so nothing to commit


def test_a_changed_source_updates_its_file_and_the_timestamp(kdir):
    ks.run(directory=kdir, log=lambda m: None)
    first = json.loads((kdir / "meta.json").read_text())
    STATE["kev"] = kev_doc(4)
    STATE["kev"]["dateReleased"] = "2026-10-22T15:00:00Z"
    assert ks.run(only=["kev"], directory=kdir, log=lambda m: None) == {"kev": "changed"}
    second = json.loads((kdir / "meta.json").read_text())
    assert second["sources"]["cisa_kev"]["count"] == 4 and second["sources"]["cisa_kev"]["source_date"] == "2026-10-22"
    assert second["sources"]["osv"] == first["sources"]["osv"]  # sources that were not refreshed are left alone
    assert len((kdir / "kev.jsonl").read_text().splitlines()) == 4


def test_a_failing_or_implausible_source_keeps_the_old_file(kdir):
    ks.run(directory=kdir, log=lambda m: None)
    old = (kdir / "attack_synced.jsonl").read_text()
    STATE["fail"].add("attack")
    STATE["kev"] = kev_doc(1)  # too small to be real
    results = ks.run(directory=kdir, log=lambda m: None)
    assert results["attack"].startswith("failed") and results["kev"].startswith("failed") and results["osv"] == "unchanged"
    assert (kdir / "attack_synced.jsonl").read_text() == old and len((kdir / "kev.jsonl").read_text().splitlines()) == 3


def test_dry_run_writes_nothing_and_the_exit_code_reports_failures(kdir):
    assert ks.run(directory=kdir, dry_run=True, log=lambda m: None) == {"kev": "changed", "osv": "changed", "attack": "changed"}
    assert sorted(p.name for p in kdir.iterdir()) == ["watchlist.txt"]
    object.__setattr__(settings, "knowledge_dir", kdir)
    try:
        assert ks.main(["--only", "kev"]) == 0
        STATE["fail"].add("kev")
        assert ks.main(["--only", "kev"]) == 2
        with pytest.raises(SystemExit):
            ks.main(["--only", "nonsense"])
    finally:
        object.__setattr__(settings, "knowledge_dir", Path(__file__).resolve().parent.parent / "knowledge")


# ---- how the app uses the files --------------------------------------------------------------------------------------------------
@pytest.fixture
def kb_dir(tmp_path):
    """A copy of the real knowledge files plus a synced overlay, so the loader can be tested in isolation."""
    d = tmp_path / "kb"
    shutil.copytree(Path(__file__).resolve().parent.parent / "knowledge", d, ignore=shutil.ignore_patterns("*_synced.jsonl", "kev.jsonl", "meta.json"))
    return d


def make_kb(d):
    return KnowledgeBase(replace(settings, knowledge_dir=d, offline=True), persist=False)


def synced_cve(id_, pkg="requests", cvss=5.0, **kw):
    return {"id": id_, "package": pkg, "ecosystem": "pypi", "affected": "<9", "fixed": "9", "cvss": cvss, "severity": "MEDIUM", "title": f"{id_} title",
            "description": f"{id_} description", "source": "OSV", "osv_id": f"OSV-{id_}", "aliases": [], "kev": False, **kw}


def test_hand_written_records_win_and_synced_ones_are_added(kb_dir):
    curated = json.loads((kb_dir / "cves.jsonl").read_text().splitlines()[0])
    mine = {**synced_cve(curated["id"]), "title": "SYNCED OVERRIDE"}
    (kb_dir / "cves_synced.jsonl").write_text("".join(json.dumps(r) + "\n" for r in [mine, synced_cve("CVE-2099-0001")]))
    kb = make_kb(kb_dir)
    assert kb.get("cves", curated["id"])["title"] == curated["title"]  # the pinned record is not overwritten
    assert kb.get("cves", "CVE-2099-0001")["source"] == "OSV"
    assert len(kb.all("cves")) == 16 + 1


def test_only_the_most_important_synced_cves_are_embedded_but_all_are_matchable(kb_dir, monkeypatch):
    monkeypatch.setattr("secagents.rag.store.INDEX_SYNCED_CVES", 3)
    rows = [synced_cve(f"CVE-2099-{i:04d}", cvss=float(i % 10)) for i in range(50)] + [synced_cve("CVE-2099-9999", cvss=1.0, kev=True)]
    (kb_dir / "cves_synced.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    kb = make_kb(kb_dir)
    assert len(kb.all("cves")) == 16 + 51  # every advisory is available for version matching
    indexed = set(kb._collection("cves").get()["ids"])
    assert len(indexed) == 16 + 3 and "CVE-2099-9999" in indexed  # curated + the known-exploited one + the highest scores


def test_changed_records_are_refreshed_in_the_index_and_vanished_ones_removed(kb_dir):
    (kb_dir / "attack_synced.jsonl").write_text("".join(json.dumps(r) + "\n" for r in [
        {"id": "T2000", "name": "Old Name", "tactic": "Execution", "description": "alpha beta", "detection": "", "mitigation": ""},
        {"id": "T2001", "name": "Doomed", "tactic": "Execution", "description": "gamma", "detection": "", "mitigation": ""}]))
    kb = make_kb(kb_dir)
    assert "Old Name" in kb._collection("attack").get(ids=["T2000"])["documents"][0]
    (kb_dir / "attack_synced.jsonl").write_text(json.dumps({"id": "T2000", "name": "New Name", "tactic": "Execution", "description": "alpha beta", "detection": "", "mitigation": ""}) + "\n")
    kb.ingest()  # what happens on the next start after the daily sync
    col = kb._collection("attack")
    assert "New Name" in col.get(ids=["T2000"])["documents"][0] and col.get(ids=["T2001"])["ids"] == []


def test_a_half_written_synced_file_does_not_break_the_app(kb_dir):
    (kb_dir / "attack_synced.jsonl").write_text('{"id": "T2000", "name": "ok", "tactic": "x", "description": "d", "detection": "", "mitigation": ""}\n{"id": "T20')
    assert make_kb(kb_dir).get("attack", "T2000")["name"] == "ok"


def test_the_shipped_files_hold_real_synced_data():
    d = Path(__file__).resolve().parent.parent / "knowledge"
    meta = json.loads((d / "meta.json").read_text())
    assert {"cisa_kev", "osv", "mitre_attack"} <= set(meta["sources"]) and meta["updated_at"]
    assert meta["sources"]["cisa_kev"]["count"] >= 500 and meta["sources"]["mitre_attack"]["count"] >= 150
    kev = [json.loads(line) for line in (d / "kev.jsonl").read_text(encoding="utf-8").splitlines()]
    assert "CVE-2021-44228" in {r["id"] for r in kev}  # Log4Shell is on CISA's list
    attack = {json.loads(line)["id"] for line in (d / "attack_synced.jsonl").read_text(encoding="utf-8").splitlines()}
    assert {"T1110", "T1190", "T1046"} <= attack
    assert (d / "cves_synced.jsonl").stat().st_size > 10_000 and (d / "watchlist.txt").exists()


def test_footer_text_and_kev_lookup(tmp_path, monkeypatch):
    d = tmp_path / "k"
    d.mkdir()
    monkeypatch.setattr(knowledge, "settings", replace(settings, knowledge_dir=d))
    assert "built-in demo data" in knowledge.footer_text() and knowledge.kev_ids() == frozenset() and knowledge.source_table() == []
    (d / "kev.jsonl").write_text(json.dumps({"id": "CVE-2021-44228", "name": "Log4Shell"}) + "\n")
    (d / "meta.json").write_text(json.dumps({"updated_at": "2026-10-23T05:17:00Z", "sources": {
        "cisa_kev": {"count": 1583, "source_date": "2026-10-22", "updated": "2026-10-22T05:00:00Z", "url": "u"},
        "osv": {"count": 4210}, "mitre_attack": {"version": "20.0", "count": 706}}}))
    text = knowledge.footer_text()
    assert text == "Knowledge updated 2026-10-23 UTC · CISA KEV 1,583 (catalog 2026-10-22) · OSV 4,210 advisories · MITRE ATT&CK v20.0"
    assert "CVE-2021-44228" in knowledge.kev_ids() and knowledge.kev_record("cve-2021-44228")["name"] == "Log4Shell" and knowledge.kev_record("CVE-1") is None
    assert [r["Source"] for r in knowledge.source_table()][0].startswith("CISA")
    (d / "meta.json").write_text("{broken")
    assert "built-in demo data" in knowledge.footer_text()


# ---- live OSV lookup ----------------------------------------------------------------------------------------------------------------
class FakeOsv:
    def __init__(self, monkeypatch):
        self.posts, self.gets, self.down = [], [], False
        self.vulns = {"PYSEC-2018-28": adv(), "GHSA-aaaa-bbbb-cccc": adv(osv_id="GHSA-aaaa-bbbb-cccc", cve=None, name="flask",
                                                                         ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}])}
        monkeypatch.setattr(osv, "_post", self.post)
        monkeypatch.setattr(osv, "_get", self.get)
        monkeypatch.setattr(osv, "live_enabled", lambda: True)

    def post(self, path, body):
        if self.down:
            raise osv.requests.ConnectionError("no route")
        self.posts.append(body)
        hits = {"requests": ["PYSEC-2018-28"], "flask": ["GHSA-aaaa-bbbb-cccc"]}
        return {"results": [{"vulns": [{"id": i} for i in hits.get(q["package"]["name"], [])]} for q in body["queries"]]}

    def get(self, path):
        self.gets.append(path)
        return self.vulns[path.rsplit("/", 1)[1]]


INVENTORY = [{"name": "requests", "version": "2.19.1", "ecosystem": "pypi", "source": "requirements.txt"},
             {"name": "Flask", "version": "0.12.2", "ecosystem": "pypi", "source": "requirements.txt"},
             {"name": "pkg", "version": "unpinned", "ecosystem": "pypi", "source": "requirements.txt"},
             {"name": "openssl", "version": "3.0.1", "ecosystem": "os", "source": "config"}]


def test_live_lookup_asks_osv_about_exact_pinned_pypi_versions_only(monkeypatch, tmp_path):
    fake = FakeOsv(monkeypatch)
    matches, info = osv.live_lookup(INVENTORY, osv.Cache(Db(tmp_path / "c.db")))
    assert [q["package"]["name"] for q in fake.posts[0]["queries"]] == ["requests", "flask"]  # no unpinned, no OS packages
    assert {m["package"]: (m["id"], m["installed"]) for m in matches} == {"requests": ("CVE-2018-18074", "2.19.1"), "flask": ("GHSA-aaaa-bbbb-cccc", "0.12.2")}
    assert info == {"queried": 2, "advisories": 2, "cached": 0, "error": ""}


def test_answers_are_cached_so_a_second_scan_makes_no_requests(monkeypatch, tmp_path):
    fake = FakeOsv(monkeypatch)
    cache = osv.Cache(Db(tmp_path / "c.db"))
    osv.live_lookup(INVENTORY, cache)
    calls = (len(fake.posts), len(fake.gets))
    matches, info = osv.live_lookup(INVENTORY, cache)
    assert (len(fake.posts), len(fake.gets)) == calls and info["cached"] == 2 and len(matches) == 2


def test_an_unreachable_osv_never_breaks_a_scan(monkeypatch, tmp_path):
    fake = FakeOsv(monkeypatch)
    fake.down = True
    matches, info = osv.live_lookup(INVENTORY, osv.Cache(Db(tmp_path / "c.db")))
    assert matches == [] and "ConnectionError" in info["error"]


def test_nothing_is_asked_when_offline_or_nothing_is_pinned(monkeypatch, tmp_path):
    fake = FakeOsv(monkeypatch)
    monkeypatch.setattr(osv, "live_enabled", lambda: False)
    assert osv.live_lookup(INVENTORY, osv.Cache(Db(tmp_path / "c.db")))[0] == [] and fake.posts == []
    monkeypatch.setattr(osv, "live_enabled", lambda: True)
    assert osv.live_lookup([INVENTORY[2], INVENTORY[3]], osv.Cache(Db(tmp_path / "c2.db")))[1]["queried"] == 0 and fake.posts == []


def test_live_switch_follows_offline_mode_and_the_environment(monkeypatch):
    monkeypatch.setattr(osv, "settings", replace(settings, offline=True))
    assert osv.live_enabled() is False
    monkeypatch.setattr(osv, "settings", replace(settings, offline=False))
    monkeypatch.setenv("OSV_LIVE", "0")
    assert osv.live_enabled() is False
    monkeypatch.setenv("OSV_LIVE", "1")
    assert osv.live_enabled() is True


def test_live_results_are_merged_without_duplicating_what_the_local_files_already_say(monkeypatch, tmp_path):
    FakeOsv(monkeypatch)
    live, _ = osv.live_lookup(INVENTORY, osv.Cache(Db(tmp_path / "c.db")))
    local = [{"cve": "CVE-2018-18074", "package": "requests", "installed": "2.19.1", "cvss": 7.5, "severity": "HIGH", "osv_id": "", "title": "t", "fixed": "2.20.0"}]
    merged = merge_live(local, live, INVENTORY)
    assert [m["cve"] for m in merged] == ["CVE-2018-18074", "GHSA-aaaa-bbbb-cccc"]  # requests is not listed twice
    added = merged[1]
    assert added["data_source"] == "OSV (live)" and added["fixed"] == "1.0" and added["source"] == "requirements.txt" and added["ecosystem"] == "pypi"


def test_threat_intel_reports_live_findings_and_known_exploited_flags(monkeypatch, tmp_path):
    from secagents.graph import run

    state = dict(run())
    base = {m["cve"] for m in state["threat_intel"]["cve_matches"]}
    live = [{**osv.advisory_to_records(adv(osv_id="GHSA-live-only-0001", cve="CVE-2099-1111", name="requests"))[0], "installed": "2.19.1"}]
    monkeypatch.setattr(osv, "live_lookup", lambda inv: (live, {"queried": 1, "advisories": 1, "cached": 0, "error": ""}))
    monkeypatch.setattr(osv, "live_enabled", lambda: True)
    monkeypatch.setattr(threat_intel, "kev_ids", lambda: frozenset({"CVE-2099-1111"}))
    again = threat_intel.run_threat_intel(state)["threat_intel"]
    row = next(m for m in again["cve_matches"] if m["cve"] == "CVE-2099-1111")
    assert row["data_source"] == "OSV (live)" and row["exploited_in_the_wild"] is True
    assert base <= {m["cve"] for m in again["cve_matches"]}  # nothing local was lost
    assert any("OSV live lookup: 1 package versions checked" in t for t in again["rag_trace"])


# ---- agent tools ----------------------------------------------------------------------------------------------------------------------
def test_agent_tools_check_kev_and_osv(monkeypatch, tmp_path):
    from secagents.tools import ToolContext, call_tool

    ctx = ToolContext()
    d = tmp_path / "k"
    d.mkdir()
    monkeypatch.setattr(knowledge, "settings", replace(settings, knowledge_dir=d))
    assert "not been loaded" in call_tool("check_known_exploited", {"id": "CVE-2021-44228"}, ctx)
    (d / "kev.jsonl").write_text(json.dumps({"id": "CVE-2021-44228", "name": "Log4Shell", "date_added": "2021-12-10"}) + "\n")
    (d / "meta.json").write_text(json.dumps({"sources": {"cisa_kev": {"count": 1}}}))
    assert json.loads(call_tool("check_known_exploited", {"id": "cve-2021-44228"}, ctx))["known_exploited"] is True
    assert json.loads(call_tool("check_known_exploited", {"id": "CVE-2000-0001"}, ctx))["known_exploited"] is False
    FakeOsv(monkeypatch)
    monkeypatch.setattr(osv, "Cache", _Mem)
    out = json.loads(call_tool("check_package_vulnerabilities", {"package": "requests", "version": "2.19.1"}, ctx))
    assert out["advisories"] == 1 and out["results"][0]["id"] == "CVE-2018-18074" and out["source"] == "OSV.dev (live)"
    assert "exact version" in call_tool("check_package_vulnerabilities", {"package": "requests", "version": "latest"}, ctx)
    monkeypatch.setattr(osv, "live_enabled", lambda: False)
    assert "switched off" in call_tool("check_package_vulnerabilities", {"package": "requests", "version": "2.19.1"}, ctx)


class _Mem:
    """An in-memory stand-in for osv.Cache (the tool builds its own cache)."""

    def __init__(self):
        self.d = {}

    def get(self, key):
        return self.d.get(key)

    def put(self, key, value):
        self.d[key] = value


def test_a_hand_written_record_outranks_an_equally_close_synced_one(kb_dir):
    curated = json.loads((kb_dir / "attack.jsonl").read_text().splitlines()[0])
    twin = {**curated, "id": "T9999"}  # identical text, so the vector distance is identical
    (kb_dir / "attack_synced.jsonl").write_text(json.dumps(twin) + "\n")
    kb = make_kb(kb_dir)
    query = f"{curated['name']} {curated['description']}"
    assert [h["id"] for h in kb.search("attack", query, k=2)] == [curated["id"], "T9999"]


def test_the_footer_shows_when_the_knowledge_was_last_updated():
    from pathlib import Path as P
    from streamlit.testing.v1 import AppTest

    app = str(P(__file__).resolve().parent.parent / "app" / "streamlit_app.py")
    at = AppTest.from_file(app, default_timeout=120).run()
    assert not at.exception
    line = [c.value for c in at.caption if c.value.startswith("📚")]
    assert line and line[0].startswith("📚 Knowledge updated 20") and "CISA KEV" in line[0] and "OSV" in line[0] and "MITRE ATT&CK v" in line[0]
    sources = [e for e in at.expander if e.label == "About Cyber Security AI Agent"][0]
    assert any("Knowledge sources" in m.value for m in sources.markdown)


def test_the_top_tagline_also_shows_when_the_knowledge_was_updated():
    from pathlib import Path as P
    from streamlit.testing.v1 import AppTest

    app = str(P(__file__).resolve().parent.parent / "app" / "streamlit_app.py")
    at = AppTest.from_file(app, default_timeout=120).run()
    tagline = next(m.value for m in at.markdown if "sa-tagline" in m.value)
    cta = "(Scan your GitHub Repositories, own logs, code and config files now)"
    assert cta in tagline and "📚 Knowledge updated 20" in tagline
    assert tagline.index(cta) < tagline.index("📚 Knowledge updated")  # appended after the call to action
    assert "MITRE ATT&amp;CK" in tagline  # escaped for HTML


def test_the_top_knowledge_line_is_white():
    from pathlib import Path as P
    from streamlit.testing.v1 import AppTest

    app = str(P(__file__).resolve().parent.parent / "app" / "streamlit_app.py")
    at = AppTest.from_file(app, default_timeout=120).run()
    css = " ".join(m.value for m in at.markdown if ".sa-knowledge" in m.value)
    rule = css[css.index(".sa-knowledge{"):].split("}")[0]
    assert "color:#fff" in rule and "opacity" not in rule  # pure white, not dimmed


def test_a_search_still_answers_when_the_vector_index_cannot_be_read(kb_dir, monkeypatch):
    kb = make_kb(kb_dir)
    monkeypatch.setattr("secagents.rag.store.time", types.SimpleNamespace(sleep=lambda s: None))
    real_get = type(kb._collection("attack")).get

    class Broken:
        """A collection whose vector index is not ready: queries fail, and so does reading vectors, but text is readable."""

        def query(self, **kw):
            raise RuntimeError("Error creating hnsw segment reader: Nothing found on disk")

        def get(self, **kw):
            if "embeddings" in kw.get("include", []):
                raise RuntimeError("Nothing found on disk")
            return real_get(kb._collection("attack"), **kw)

    ids, dists, docs = kb._query(Broken(), [[0.0] * 512], 3, query_text="brute force password guessing ssh")
    assert len(ids) == 3 and any("Brute Force" in d for d in docs) and dists == sorted(dists)  # ranked by word overlap, best first
