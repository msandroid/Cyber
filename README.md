# サイバー攻撃事例データベース

国内外のセキュリティ報道と公的機関の公開情報から、サイバー攻撃の事例を自動で集めて検索・閲覧できるようにするデータベースです。

- **閲覧画面**: `docs/index.html`。キーワード検索、区分・攻撃種別・業種・国・攻撃者・収集元・言語・期間での絞り込み、集計、CSV保存ができます。絞り込み条件は URL に残るので、そのまま共有できます。
- **データ**: `docs/data/incidents.json`（正本）と、`build-db` で作る SQLite の `data/incidents.db`（全文検索付き）。
- **収集**: `collector/collect.py`。Python 標準ライブラリだけで動きます。GitHub Actions で 1 日 2 回自動実行されます。

## 収集元

| 収集元 | 言語 | 取得方法 | URL 確認 |
|---|---|---|---|
| JPCERT/CC | 日本語 | RSS | 未確認 |
| IPA | 日本語 | RSS | 未確認 |
| 警察庁 サイバー警察局 | 日本語 | 新着情報ページのリンク抽出 | 確認済み |
| Security NEXT | 日本語 | RSS | 確認済み |
| ITmedia @IT | 日本語 | RSS | 確認済み |
| ロケットボーイズ | 日本語 | RSS | 未確認 |
| BleepingComputer | 英語 | RSS | 確認済み |
| The Record | 英語 | RSS | 確認済み |
| The Hacker News | 英語 | RSS | 確認済み |
| Security Affairs | 英語 | RSS | 確認済み |
| CM-Alliance | 英語 | 月次まとめ記事のリンク抽出 | 確認済み |
| CISA KEV | 英語 | JSON（直近 120 日の追加分） | 未確認 |
| ransomware.live | 英語 | API（リークサイト掲載情報） | 未確認 |

「未確認」のソースはフィードの URL を推定で設定しています。取得に失敗すると、閲覧画面の「収集元」タブにエラーが表示されます。その場合は社名で検索して正しいフィード URL を探し、`config/sources.json` の `url` を書き換えてください。

## 使い方

```bash
python collector/collect.py collect          # 全ソースから収集して docs/data/ を更新
python collector/collect.py collect -s jpcert -s ipa   # 一部のソースだけ収集
python collector/collect.py seed             # 初期データ（collector/seed.json）だけ取り込む。ネット接続不要
python collector/collect.py import feed.xml -s security_next   # 手元のフィードファイルを取り込む
python collector/collect.py reclassify       # 分類ルールを変えた後に全件を分類し直す
python collector/collect.py build-db         # SQLite データベース data/incidents.db を作る
```

閲覧画面はローカルで次のように開きます（`file://` で直接開くとデータを読み込めません）。

```bash
python -m http.server 8000 -d docs
```

ブラウザで http://localhost:8000/ を開いてください。

### Web で公開する（GitHub Pages）

リポジトリの Settings → Pages で、Source を「Deploy from a branch」、ブランチをデフォルトブランチ、フォルダを `/docs` にします。GitHub Actions の自動収集（`.github/workflows/collect.yml`）がデータを更新してコミットするので、公開ページも自動で最新になります。

### SQLite で検索する

```sql
-- 全文検索（3 文字以上。trigram で日本語も検索できる）
SELECT i.published, i.victim, i.title, i.url
FROM incidents_fts f JOIN incidents i ON i.rowid = f.rowid
WHERE incidents_fts MATCH '佐川急便';

-- ランサムウェアの被害事例を月別に数える
SELECT substr(i.published, 1, 7) AS month, count(*)
FROM incidents i JOIN tags t ON t.incident_id = i.id
WHERE i.kind = 'incident' AND t.facet = 'attack_type' AND t.value = 'ransomware'
GROUP BY month ORDER BY month DESC;
```

2 文字以下の語（例: 「流出」）は FTS では検索できないので、`WHERE title LIKE '%流出%'` を使ってください。

## データ項目

| 項目 | 内容 |
|---|---|
| `kind` | 区分。`incident`（被害事例）、`mishandling`（誤送信・誤公開・紛失など攻撃以外の事故）、`vulnerability`（脆弱性・悪用）、`enforcement`（摘発・テイクダウン）、`advisory`（注意喚起・脅威動向）、`summary`（月次まとめ） |
| `attack_types` | 攻撃種別。ランサムウェア、情報流出、不正アクセス・侵害、脆弱性悪用、フィッシング・詐欺、DDoS、サプライチェーン、マルウェア、国家系・諜報、暗号資産窃取、AI悪用 |
| `victim` | 被害組織（タイトルからの推定） |
| `sectors` / `countries` / `actors` | 業種、国・地域、攻撃者・グループ |
| `published` / `first_seen` | 記事の公開日、初めて収集した日時 |
| `claim_unverified` | ransomware.live 由来など、攻撃者側の主張で未検証のもの |
| `curated` / `notes` | `config/overrides.json` で手動修正した項目と補足 |

## 分類の仕組みと修正方法

区分・攻撃種別・業種・国・被害組織は `collector/classify.py` のキーワードルールで自動推定しています。誤りを含むことがあるので、正確な内容はリンク先の原文で確認してください。

個別の誤りは `config/overrides.json` に記事 URL をキーにして書くと上書きできます。

```json
{
  "https://www.security-next.com/191994": {
    "victim": "バンダイロジパル（バンダイナムコHD子会社）",
    "notes": "補足メモ"
  }
}
```

ルール自体を直したときは `python collector/collect.py reclassify` で全件に反映されます。

## 初期データについて

開発環境からは各サイトに直接アクセスできなかったため、2026-10-30 時点で各ソースのフィードと一覧ページを別経路で取得し、その記事（タイトル・URL・日付・要約は原文のまま）を `collector/seed.json` に入れています（52 件）。以後は `collect` の実行で各サイトから直接取得します。

## テスト

```bash
python -m unittest discover -s tests
```
