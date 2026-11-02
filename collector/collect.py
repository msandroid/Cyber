#!/usr/bin/env python3
"""サイバー攻撃事例データベースの収集スクリプト（標準ライブラリのみ）。

使い方:
  python collector/collect.py collect              全ソースから収集して docs/data/ を更新
  python collector/collect.py collect -s jpcert    指定ソースのみ
  python collector/collect.py seed                 初期データ (collector/seed.json) だけ取り込む
  python collector/collect.py import FILE -s ID    手元のフィードファイルを取り込む
  python collector/collect.py reclassify           分類ルール変更後に全件を再分類
  python collector/collect.py build-db             data/incidents.db (SQLite + 全文検索) を生成
"""

import argparse
import datetime as dt
import email.utils
import hashlib
import html
import json
import re
import sqlite3
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import classify  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "config" / "sources.json"
OVERRIDES_FILE = ROOT / "config" / "overrides.json"
SEED_FILE = ROOT / "collector" / "seed.json"
DATA_DIR = ROOT / "docs" / "data"
INCIDENTS_FILE = DATA_DIR / "incidents.json"
STATUS_FILE = DATA_DIR / "status.json"
DB_FILE = ROOT / "data" / "incidents.db"

USER_AGENT = "Mozilla/5.0 (compatible; CyberIncidentDB/1.0; +https://github.com/msandroid/Cyber)"
TIMEOUT = 30
SUMMARY_MAX = 400

NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "rss1": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


# ---------------------------------------------------------------- 共通

def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def record_id(*parts):
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def clean_text(s):
    if not s:
        return ""
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s).strip()
    s = s.replace("[...]", "").strip()
    return s[:SUMMARY_MAX]


def parse_date(s):
    """RFC822 / ISO8601 / 和暦(R8.10.16) / 2026年10月16日 / 16 October 2026 を YYYY-MM-DD に。"""
    if not s:
        return None
    s = s.strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
        if d:
            return d.date().isoformat()
    except (TypeError, ValueError, IndexError):
        pass
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return "-".join(m.groups())
    m = re.search(r"[RＲ令和]\s*(\d{1,2})[.．年](\d{1,2})[.．月](\d{1,2})", s)
    if m:
        y, mo, d = (int(x) for x in m.groups())
        return dt.date(2018 + y, mo, d).isoformat()
    m = re.search(r"(\d{4})年(\d{1,2})月(\d{1,2})日", s)
    if m:
        return dt.date(*(int(x) for x in m.groups())).isoformat()
    m = re.search(r"(\d{1,2}) (January|February|March|April|May|June|July|August|September|October|"
                  r"November|December) (\d{4})", s)
    if m:
        return dt.datetime.strptime(" ".join(m.groups()), "%d %B %Y").date().isoformat()
    return None


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    last = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - ネットワーク例外は種類を問わず再試行
            last = e
    raise last


def make_record(source, title, url, published, summary, extra=None, rid=None):
    title = clean_text(title)
    summary = clean_text(summary)
    info = (extra or {}).pop("_classified", None) or classify.classify(title, summary, source["lang"])
    if info is None:
        return None
    if source.get("default_kind"):
        info["kind"] = source["default_kind"]
    rec = {
        "id": rid or record_id(url),
        "title": title,
        "url": url,
        "source_id": source["id"],
        "source_name": source["name"],
        "lang": source["lang"],
        "published": published,
        "summary": summary,
        **info,
    }
    if extra:
        rec.update(extra)
    return rec


# ---------------------------------------------------------------- パーサ

def parse_feed(data, source):
    """RSS 2.0 / RSS 1.0 (RDF) / Atom を解析してレコードのリストを返す。"""
    if b"<!ENTITY" in (data if isinstance(data, bytes) else data.encode()):
        raise ValueError("DTD entity declarations are not accepted")  # XXE / billion laughs 対策
    root = ET.fromstring(data)
    items = []
    if root.tag == f"{{{NS['atom']}}}feed":
        for e in root.findall("atom:entry", NS):
            link = e.find("atom:link[@rel='alternate']", NS)
            if link is None:
                link = e.find("atom:link", NS)
            items.append((
                e.findtext("atom:title", "", NS),
                link.get("href") if link is not None else "",
                e.findtext("atom:published", None, NS) or e.findtext("atom:updated", None, NS),
                e.findtext("atom:summary", "", NS) or e.findtext("atom:content", "", NS),
            ))
    elif root.tag.endswith("RDF"):
        for e in root.findall("rss1:item", NS):
            items.append((
                e.findtext("rss1:title", "", NS),
                e.findtext("rss1:link", "", NS) or e.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about", ""),
                e.findtext("dc:date", None, NS),
                e.findtext("rss1:description", "", NS),
            ))
    else:
        for e in root.iter("item"):
            items.append((
                e.findtext("title", ""),
                e.findtext("link", "") or e.findtext("guid", ""),
                e.findtext("pubDate", None) or e.findtext("dc:date", None, NS),
                e.findtext("description", "") or e.findtext("content:encoded", "", NS),
            ))
    out = []
    for title, link, date, summary in items:
        link = (link or "").strip()
        if not link or not title:
            continue
        rec = make_record(source, title, link, parse_date(date), summary)
        if rec:
            out.append(rec)
    return out


_A_TAG = re.compile(r"<a\s[^>]*?href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)


def parse_html_links(data, source, today=None):
    """一覧ページから link_pattern に一致するリンクを記事として抽出する（RSS が無いサイト用）。"""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    pattern = re.compile(source["link_pattern"])
    seen, out = set(), []
    for href, inner in _A_TAG.findall(text):
        url = urllib.parse.urljoin(source["url"], html.unescape(href))
        if url in seen or not pattern.match(url):
            continue
        title = clean_text(inner)
        if not title:
            continue
        seen.add(url)
        published = parse_date(title)
        title = re.sub(r"\s*[（(][RＲ令和]\s*\d+[.．年]\d+[.．月]\d+日?[)）]\s*", " ", title).strip()
        title = re.sub(r"\s*PDFファイルを開く\s*$", "", title)
        rec = make_record(source, title, url, published or today or dt.date.today().isoformat(), "",
                          {"date_estimated": published is None})
        if rec:
            out.append(rec)
    return out


def parse_cisa_kev(data, source, today=None):
    doc = json.loads(data)
    today = dt.date.fromisoformat(today) if today else dt.date.today()
    cutoff = today - dt.timedelta(days=source.get("max_age_days", 120))
    out = []
    for v in doc.get("vulnerabilities", []):
        added = v.get("dateAdded")
        if not added or dt.date.fromisoformat(added) < cutoff:
            continue
        cve = v.get("cveID", "")
        types = ["vuln_exploit"]
        if v.get("knownRansomwareCampaignUse") == "Known":
            types.append("ransomware")
        info = {
            "kind": "vulnerability", "attack_types": types, "sectors": [], "countries": [],
            "actors": [], "victim": None,
        }
        summary = f"{v.get('vendorProject', '')} {v.get('product', '')}: {v.get('shortDescription', '')}"
        rec = make_record(source, f"{cve} {v.get('vulnerabilityName', '')}",
                          f"https://nvd.nist.gov/vuln/detail/{cve}", added, summary,
                          {"_classified": info, "cve": cve}, rid=record_id("kev", cve))
        out.append(rec)
    return out


def _first(d, *keys):
    for k in keys:
        if d.get(k):
            return d[k]
    return None


def parse_ransomware_live(data, source):
    """ransomware.live のリークサイト掲載情報。掲載＝攻撃者側の主張であり未検証。"""
    doc = json.loads(data)
    if isinstance(doc, dict):
        doc = _first(doc, "victims", "data", "results") or []
    out = []
    for v in doc:
        name = _first(v, "victim", "post_title", "name")
        group = _first(v, "group", "group_name")
        if not name or not group:
            continue
        date = parse_date(str(_first(v, "attackdate", "discovered", "published", "date") or ""))
        country = (_first(v, "country") or "").upper()
        sector = _first(v, "activity", "sector")
        url = _first(v, "url", "post_url") or f"https://www.ransomware.live/group/{urllib.parse.quote(group)}"
        info = {
            "kind": "incident", "attack_types": ["ransomware"],
            "sectors": [sector] if sector and sector != "Not Found" else [],
            "countries": [country] if re.fullmatch(r"[A-Z]{2}", country) else [],
            "actors": [group], "victim": name,
        }
        summary = (_first(v, "description", "summary") or "") or f"{group} のリークサイトに掲載（攻撃者側の主張・未検証）"
        rec = make_record(source, f"{name} — {group} のリークサイトに掲載", url, date, summary,
                          {"_classified": info, "claim_unverified": True},
                          rid=record_id("rwlive", group, name, date or ""))
        out.append(rec)
    return out


def parse_source(data, source, today=None):
    t = source["type"]
    if t == "rss":
        return parse_feed(data, source)
    if t == "html_links":
        return parse_html_links(data, source, today)
    if t == "cisa_kev":
        return parse_cisa_kev(data, source, today)
    if t == "ransomware_live":
        return parse_ransomware_live(data, source)
    raise ValueError(f"unknown source type: {t}")


# ---------------------------------------------------------------- 保存

def load_json(path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def load_sources():
    return load_json(SOURCES_FILE, {"sources": []})["sources"]


def apply_overrides(rec, overrides):
    o = overrides.get(rec["id"]) or overrides.get(rec["url"])
    if o:
        rec.update(o)
        rec["curated"] = True
    return rec


def merge(existing, new_records, overrides):
    by_id = {r["id"]: r for r in existing}
    added = 0
    stamp = now_iso()
    for rec in new_records:
        old = by_id.get(rec["id"])
        if old:
            rec["first_seen"] = old.get("first_seen", stamp)
            if not rec.get("published"):
                rec["published"] = old.get("published")
        else:
            rec["first_seen"] = stamp
            added += 1
        by_id[rec["id"]] = apply_overrides(rec, overrides)
    records = sorted(by_id.values(), key=lambda r: (r.get("published") or "", r["first_seen"]), reverse=True)
    return records, added


def save_incidents(records):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    doc = {"generated_at": now_iso(), "count": len(records), "records": records}
    INCIDENTS_FILE.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def load_incidents():
    return load_json(INCIDENTS_FILE, {"records": []})["records"]


def write_status(results, sources):
    status = load_json(STATUS_FILE, {"sources": {}})
    for s in sources:
        st = status["sources"].setdefault(s["id"], {})
        st.update({"name": s["name"], "home": s["home"], "url": s["url"], "lang": s["lang"]})
        if s["id"] in results:
            st.update(results[s["id"]])
    status["updated_at"] = now_iso()
    STATUS_FILE.write_text(json.dumps(status, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- コマンド

def cmd_collect(args):
    sources = [s for s in load_sources() if not args.source or s["id"] in args.source]
    overrides = load_json(OVERRIDES_FILE, {})
    records = load_incidents()
    results, collected = {}, []
    for s in sources:
        try:
            recs = parse_source(fetch(s["url"]), s)
            collected.extend(recs)
            results[s["id"]] = {"ok": True, "last_success": now_iso(), "last_count": len(recs), "error": None}
            print(f"[ok]   {s['id']:<18} {len(recs):>4} 件")
        except Exception as e:  # noqa: BLE001 - 1ソースの失敗で全体を止めない
            results[s["id"]] = {"ok": False, "last_attempt": now_iso(), "error": f"{type(e).__name__}: {e}"}
            print(f"[fail] {s['id']:<18} {type(e).__name__}: {e}", file=sys.stderr)
    if args.seed or not records:
        collected = load_json(SEED_FILE, {"records": []}).get("records", []) + collected
        collected = [reparse_seed(r) for r in collected]
        collected = [r for r in collected if r]
    records, added = merge(records, collected, overrides)
    save_incidents(records)
    write_status(results, load_sources())
    print(f"新規 {added} 件 / 合計 {len(records)} 件 -> {INCIDENTS_FILE.relative_to(ROOT)}")
    failed = [k for k, v in results.items() if not v["ok"]]
    return 1 if failed and len(failed) == len(results) else 0


def reparse_seed(r):
    """seed.json の行（title/url/published/summary/source_id のみ）を通常レコードに変換する。"""
    if "kind" in r:
        return r
    sources = {s["id"]: s for s in load_sources()}
    return make_record(sources[r["source_id"]], r["title"], r["url"], parse_date(r.get("published")),
                       r.get("summary", ""))


def cmd_seed(_args):
    recs = [reparse_seed(r) for r in load_json(SEED_FILE, {"records": []}).get("records", [])]
    records, added = merge(load_incidents(), [r for r in recs if r], load_json(OVERRIDES_FILE, {}))
    save_incidents(records)
    write_status({}, load_sources())
    print(f"seed: 新規 {added} 件 / 合計 {len(records)} 件")
    return 0


def cmd_import(args):
    sources = {s["id"]: s for s in load_sources()}
    source = sources[args.source[0]]
    recs = parse_source(Path(args.file).read_bytes(), source)
    records, added = merge(load_incidents(), recs, load_json(OVERRIDES_FILE, {}))
    save_incidents(records)
    print(f"{args.file}: {len(recs)} 件解析, 新規 {added} 件 / 合計 {len(records)} 件")
    return 0


def cmd_reclassify(_args):
    overrides = load_json(OVERRIDES_FILE, {})
    out = []
    for r in load_incidents():
        if r["source_id"] in ("cisa_kev", "ransomware_live"):
            out.append(apply_overrides(r, overrides))
            continue
        info = classify.classify(r["title"], r.get("summary", ""), r["lang"])
        if info is None:
            continue
        r.update(info)
        r.pop("curated", None)
        out.append(apply_overrides(r, overrides))
    save_incidents(out)
    print(f"再分類 {len(out)} 件")
    return 0


def cmd_build_db(_args):
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    DB_FILE.unlink(missing_ok=True)
    con = sqlite3.connect(DB_FILE)
    con.executescript("""
        CREATE TABLE incidents (
            id TEXT PRIMARY KEY, published TEXT, title TEXT, summary TEXT, url TEXT,
            source_id TEXT, source_name TEXT, lang TEXT, kind TEXT, victim TEXT,
            first_seen TEXT, claim_unverified INTEGER DEFAULT 0, curated INTEGER DEFAULT 0
        );
        CREATE TABLE tags (incident_id TEXT, facet TEXT, value TEXT);
        CREATE INDEX tags_facet ON tags (facet, value);
        CREATE INDEX incidents_published ON incidents (published);
        CREATE VIRTUAL TABLE incidents_fts USING fts5(
            title, summary, victim, content='incidents', content_rowid='rowid', tokenize='trigram'
        );
    """)
    facets = {"attack_types": "attack_type", "sectors": "sector", "countries": "country", "actors": "actor"}
    for r in load_incidents():
        con.execute(
            "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["id"], r.get("published"), r["title"], r.get("summary"), r["url"], r["source_id"],
             r["source_name"], r["lang"], r["kind"], r.get("victim"), r.get("first_seen"),
             int(bool(r.get("claim_unverified"))), int(bool(r.get("curated")))))
        for key, facet in facets.items():
            con.executemany("INSERT INTO tags VALUES (?,?,?)", [(r["id"], facet, v) for v in r.get(key, [])])
    con.execute("INSERT INTO incidents_fts(incidents_fts) VALUES ('rebuild')")
    con.commit()
    n = con.execute("SELECT count(*) FROM incidents").fetchone()[0]
    con.close()
    print(f"{n} 件 -> {DB_FILE.relative_to(ROOT)}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="全ソースから収集")
    c.add_argument("-s", "--source", action="append", help="ソースID（複数可）")
    c.add_argument("--seed", action="store_true", help="collector/seed.json も取り込む")
    c.set_defaults(func=cmd_collect)
    i = sub.add_parser("import", help="手元のフィード/JSONファイルを取り込む")
    i.add_argument("file")
    i.add_argument("-s", "--source", action="append", required=True)
    i.set_defaults(func=cmd_import)
    sub.add_parser("seed", help="collector/seed.json だけを取り込む（ネット接続不要）").set_defaults(func=cmd_seed)
    sub.add_parser("reclassify", help="全件を再分類").set_defaults(func=cmd_reclassify)
    sub.add_parser("build-db", help="SQLite データベースを生成").set_defaults(func=cmd_build_db)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
