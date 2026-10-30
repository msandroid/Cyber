import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collector"))

import classify  # noqa: E402
import collect  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
JA = {"id": "t_ja", "name": "T", "lang": "ja", "type": "rss", "url": "https://example.jp/"}
EN = {"id": "t_en", "name": "T", "lang": "en", "type": "rss", "url": "https://example.com/"}


class ParseTest(unittest.TestCase):
    def test_rss2_filters_pr_and_unrelated(self):
        recs = collect.parse_feed((FIX / "rss2.xml").read_bytes(), JA)
        self.assertEqual([r["url"] for r in recs], ["https://example.jp/a"])
        r = recs[0]
        self.assertEqual(r["published"], "2026-10-26")
        self.assertEqual(r["kind"], "incident")
        self.assertEqual(r["victim"], "佐川急便")
        self.assertIn("data_breach", r["attack_types"])
        self.assertEqual(r["countries"], ["JP"])
        self.assertNotIn("<p>", r["summary"])

    def test_rdf(self):
        recs = collect.parse_feed((FIX / "rdf.xml").read_bytes(), JA)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["published"], "2026-10-27")
        self.assertEqual(recs[0]["kind"], "vulnerability")
        self.assertIn("vuln_exploit", recs[0]["attack_types"])

    def test_atom(self):
        recs = collect.parse_feed((FIX / "atom.xml").read_bytes(), EN)
        self.assertEqual(recs[0]["url"], "https://example.com/jal")
        self.assertEqual(recs[0]["victim"], "Japan Airlines")
        self.assertIn("JP", recs[0]["countries"])

    def test_rejects_entities(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><rss><channel></channel></rss>'
        with self.assertRaises(ValueError):
            collect.parse_feed(evil, EN)

    def test_html_links(self):
        src = {"id": "npa", "name": "NPA", "lang": "ja", "type": "html_links",
               "url": "https://www.npa.go.jp/bureau/cyber/",
               "link_pattern": r"^https://www\.npa\.go\.jp/bureau/cyber/koho/(caution|news)/[^\"]+\.html$"}
        recs = collect.parse_html_links((FIX / "npa.html").read_bytes(), src, today="2026-10-30")
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0]["published"], "2026-10-16")
        self.assertEqual(recs[0]["title"], "不正アクセスによる漏えい等事案を踏まえた注意喚起について")
        self.assertFalse(recs[0]["date_estimated"])
        self.assertEqual(recs[1]["kind"], "enforcement")
        self.assertTrue(recs[1]["date_estimated"])

    def test_kev(self):
        src = {"id": "cisa_kev", "name": "CISA KEV", "lang": "en", "type": "cisa_kev", "url": "x", "max_age_days": 30}
        recs = collect.parse_cisa_kev((FIX / "kev.json").read_bytes(), src, today="2026-10-30")
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["cve"], "CVE-2026-0001")
        self.assertEqual(recs[0]["attack_types"], ["vuln_exploit", "ransomware"])

    def test_ransomware_live(self):
        src = {"id": "ransomware_live", "name": "ransomware.live", "lang": "en", "type": "ransomware_live", "url": "x"}
        recs = collect.parse_ransomware_live((FIX / "ransomware_live.json").read_bytes(), src)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0]["victim"], "Example Corp")
        self.assertEqual(recs[0]["published"], "2026-10-28")
        self.assertEqual(recs[0]["countries"], ["JP"])
        self.assertTrue(recs[0]["claim_unverified"])
        self.assertEqual(recs[1]["actors"], ["akira"])


class DateTest(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(collect.parse_date("R8.10.16"), "2026-10-16")
        self.assertEqual(collect.parse_date("令和8年9月18日"), "2026-09-18")
        self.assertEqual(collect.parse_date("2026年10月1日"), "2026-10-01")
        self.assertEqual(collect.parse_date("1 October 2026"), "2026-10-01")
        self.assertEqual(collect.parse_date("Thu, 29 Oct 2026 20:01:25 GMT"), "2026-10-29")
        self.assertIsNone(collect.parse_date("no date"))


class ClassifyTest(unittest.TestCase):
    def kind(self, title, lang="en", summary=""):
        info = classify.classify(title, summary, lang)
        return info and info["kind"]

    def test_kinds(self):
        self.assertEqual(self.kind("Police seize Virtualine bulletproof service tied to ransomware"), "enforcement")
        self.assertEqual(self.kind("婚活イベントで申込者情報を誤公開、開催中止に - 岡山県", "ja"), "mishandling")
        self.assertEqual(self.kind("Cyberattack disrupts Belgian tax services before filing deadline"), "incident")
        self.assertEqual(self.kind("New Cisco firewall zero-day exploited to crash SSL VPN devices"), "vulnerability")

    def test_enforcement_only_from_title(self):
        k = self.kind("Hugging Face malware campaign returns to hijack GPUs",
                      summary="returned days after takedown, hijacking GPU servers")
        self.assertEqual(k, "incident")

    def test_victims(self):
        self.assertEqual(classify.victim("GMOに身代金要求 - ランサム攻撃や情報公開を行うと脅迫", "ja"), "GMO")
        self.assertEqual(classify.victim("バンナム子会社に不正アクセス - 「一番くじONLINE」配送情報が流出か", "ja"), "バンナム子会社")
        self.assertIsNone(classify.victim("脆弱性「PHP2Shell」の悪用を確認 - 米当局が注意喚起", "ja"))
        self.assertEqual(classify.victim("Binance probes potential $5.8 billion crypto-theft hack", "en"), "Binance")
        self.assertIsNone(classify.victim("Hackers exploit Cisco SD-WAN flaw", "en"))

    def test_actors(self):
        self.assertEqual(classify.actors("Rhysida claimed; APT41 and UAT-11473 seen"), ["Rhysida", "APT41", "UAT-11473"])


class MergeTest(unittest.TestCase):
    def test_merge_keeps_first_seen_and_applies_overrides(self):
        old = [{"id": "a", "url": "u1", "published": "2026-10-01", "first_seen": "2026-10-01T00:00:00+00:00"}]
        new = [{"id": "a", "url": "u1", "published": None}, {"id": "b", "url": "u2", "published": "2026-10-02"}]
        recs, added = collect.merge(old, new, {"u2": {"victim": "X"}})
        self.assertEqual(added, 1)
        by = {r["id"]: r for r in recs}
        self.assertEqual(by["a"]["first_seen"], "2026-10-01T00:00:00+00:00")
        self.assertEqual(by["a"]["published"], "2026-10-01")
        self.assertEqual(by["b"]["victim"], "X")
        self.assertTrue(by["b"]["curated"])


if __name__ == "__main__":
    unittest.main()
