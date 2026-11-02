"""記事タイトル・要約から攻撃種別、業種、国、被害組織、攻撃者を推定する。

すべてキーワードによる推定で、誤判定はありうる。修正は config/overrides.json で行う。
"""

import re

# 区分。優先順位はこの並び（上が強い）。
KIND_RULES = [
    ("enforcement", [
        r"逮捕", r"摘発", r"テイクダウン", r"検挙", r"起訴", r"送検",
        r"\barrest", r"\bseiz", r"takedown", r"take down", r"\bcharged\b", r"extradit",
        r"sentenced", r"\bsanction", r"dismantl", r"disrupted .*(botnet|operation|infrastructure)",
        r"cuts off access", r"\bbounty\b",
    ]),
    ("mishandling", [
        r"誤送信", r"誤公開", r"誤掲載", r"誤送付", r"紛失", r"置き忘れ", r"同意な[くし]",
        r"設定ミス", r"誤って",
    ]),
    ("incident", [
        r"不正アクセス", r"情報流出", r"流出", r"漏えい", r"漏洩", r"侵害", r"身代金", r"ランサム",
        r"サイバー攻撃を受け", r"サイバー攻撃被害", r"被害", r"乗っ取", r"改ざん", r"不正送金", r"システム障害",
        r"\bbreach", r"\bhacked\b", r"\bhack\b", r"cyberattack", r"cyber attack", r"cyber intrusion",
        r"ransomware attack", r"\bdisrupts?\b", r"\bstolen\b", r"\bsteal", r"\bleak", r"\bhalts?\b",
        r"\bsuffers?\b", r"\bcompromised?\b", r"\btheft\b", r"\bexposes?\b", r"\bexposed\b",
        r"\bextortion\b", r"\bhijack", r"\binfect", r"on sale", r"offered for sale",
    ]),
    ("vulnerability", [
        r"脆弱性", r"CVE-\d{4}-\d+", r"ゼロデイ", r"アップデート", r"修正",
        r"\bflaws?\b", r"zero-day", r"\bpatch", r"\bvulnerabilit", r"\bexploit", r"\bbug\b", r"\bKEV\b",
    ]),
    ("advisory", [
        r"注意喚起", r"アドバイザリ", r"警告", r"警鐘", r"フィッシング", r"マルウェア", r"攻撃",
        r"\bwarns?\b", r"advisory", r"\bphishing\b", r"\bmalware\b", r"\bcampaign\b", r"\bthreat actor",
        r"\bAPT\b", r"backdoor", r"espionage",
    ]),
]

ATTACK_TYPE_RULES = {
    "ransomware": [r"ランサム", r"身代金", r"ransom", r"\bLockBit\b", r"\bQilin\b", r"\bAkira\b",
                   r"\bRhysida\b", r"\bCl0p\b", r"\bMedusa\b", r"\bRansomHub\b", r"\bBlack ?Basta\b"],
    "data_breach": [r"情報流出", r"流出", r"漏えい", r"漏洩", r"\bdata breach", r"\bleak", r"\bexpos",
                    r"\bstolen data", r"records", r"for sale", r"on sale"],
    "unauthorized_access": [r"不正アクセス", r"侵害", r"不正ログイン", r"乗っ取", r"\bbreach", r"\bhacked\b",
                            r"\bcompromis", r"\bintrusion", r"\bhijack", r"token[- ]replay", r"\bhack\b",
                            r"stolen (tokens?|credentials?|sessions?)", r"account takeover"],
    "vuln_exploit": [r"脆弱性.*悪用", r"悪用.*脆弱性", r"ゼロデイ", r"zero-day", r"\bexploit", r"\bKEV\b",
                     r"CVE-\d{4}-\d+"],
    "phishing": [r"フィッシング", r"なりすまし", r"詐欺", r"\bphishing\b", r"impersonat", r"\bscam",
                 r"social engineering", r"device code"],
    "ddos": [r"\bDDoS\b", r"サービス妨害", r"denial[- ]of[- ]service"],
    "supply_chain": [r"サプライチェーン", r"委託先", r"取引先", r"third[- ]party", r"supply[- ]chain",
                     r"malicious (package|model|extension)", r"悪性コード.*混入", r"\bnpm\b", r"\bPyPI\b",
                     r"extensions?\b.*install"],
    "malware": [r"マルウェア", r"ウイルス", r"バックドア", r"\bmalware\b", r"\bbackdoor", r"\bRAT\b",
                r"stealer", r"botnet", r"web shell", r"\bworm\b", r"crypto[- ]?mining", r"\bminer\b",
                r"\binfect", r"skimm", r"不正アプリ"],
    "espionage": [r"\bAPT\b", r"国家", r"諜報", r"espionage", r"nation[- ]state", r"China-(linked|nexus)",
                  r"North Korea", r"北朝鮮", r"中国政府", r"Typhoon\b", r"\bLazarus\b", r"\bKimsuky\b"],
    "crypto_theft": [r"暗号資産", r"仮想通貨", r"\bcrypto(currency)?\b.*(theft|hack|drain|stol|wallet)",
                     r"(drain|theft|stole).*\bcrypto", r"\bwallet"],
    "ai_abuse": [r"\bAI\b.*(attack|agent|assisted|hack)", r"AI(エージェント|による).*攻撃", r"自律型攻撃"],
}

SECTOR_RULES = {
    "医療・福祉": [r"病院", r"医療", r"クリニック", r"介護", r"hospital", r"health", r"medical", r"clinic", r"pharma"],
    "金融・暗号資産": [r"銀行", r"証券", r"金融", r"保険", r"暗号資産", r"\bFX\b", r"\bbank(s|ing)?\b",
                  r"financial (institution|services)", r"insur", r"crypto(currency)? (exchange|platform|wallet)",
                  r"Binance", r"Polymarket", r"trading"],
    "政府・自治体": [r"政府", r"省\b", r"庁", r"県", r"市役所", r"[市区町村](?:は|が|の|$)", r"自治体", r"当局",
                r"government", r"federal", r"ministry", r"\bstate\b", r"municipal", r"\bcity\b",
                r"\bcourts?\b", r"\btax\b"],
    "教育・研究": [r"大学", r"学校", r"小中学校", r"高校", r"教育", r"universit", r"school", r"college", r"educat"],
    "製造": [r"製造", r"工場", r"メーカー", r"manufactur", r"factory", r"automotive"],
    "物流・運輸": [r"物流", r"運輸", r"配送", r"急便", r"航空", r"鉄道", r"logistic", r"shipping", r"airline",
              r"\bairways?\b", r"Airlines", r"passenger", r"rail", r"transport"],
    "小売・EC": [r"小売", r"通販", r"ECサイト", r"オンラインストア", r"retail", r"online stores?", r"e-?commerce",
              r"Magento", r"Adobe Commerce"],
    "IT・通信": [r"クラウド", r"SaaS", r"通信", r"プロバイダ", r"配信サービス", r"メール配信", r"ホスティング",
              r"cloud", r"telecom", r"hosting", r"\bISP\b", r"software", r"SaaS"],
    "エネルギー・インフラ": [r"電力", r"ガス", r"水道", r"エネルギー", r"energy", r"utility", r"utilities",
                    r"\bpower\b", r"\bwater\b", r"critical infrastructure"],
    "メディア・エンタメ": [r"出版", r"新聞", r"放送", r"ゲーム", r"publisher", r"publishing", r"broadcast",
                   r"gaming", r"entertainment", r"Condé Nast"],
}

COUNTRY_RULES = {
    "JP": [r"日本", r"国内", r"Japan", r"\bJAL\b", r"都道府県", r"[都道府県]は", r"(?:県|市|町|村)(?:は|が|の)"],
    "US": [r"米国", r"米当局", r"U\.S\.", r"\bUS\b", r"United States", r"American", r"\bfederal\b",
           r"\bFBI\b", r"\bCISA\b"],
    "UK": [r"英国", r"\bUK\b", r"United Kingdom", r"British", r"\bNHS\b"],
    "DE": [r"ドイツ", r"German", r"Berlin"],
    "BE": [r"ベルギー", r"Belgi"],
    "FR": [r"フランス", r"France", r"French"],
    "KR": [r"韓国", r"South Korea", r"Korean"],
    "UA": [r"ウクライナ", r"Ukrain"],
    "AU": [r"オーストラリア", r"豪州", r"Australia"],
    "TW": [r"台湾", r"Taiwan"],
    "VN": [r"ベトナム", r"Vietnam"],
    "IN": [r"インド\b", r"\bIndia"],
    "SG": [r"シンガポール", r"Singapore"],
}

KNOWN_ACTORS = [
    "LockBit", "Qilin", "Akira", "Rhysida", "BlackCat", "ALPHV", "Cl0p", "Clop", "Play", "Medusa",
    "RansomHub", "Black Basta", "8Base", "INC Ransom", "Hunters International", "SafePay", "DragonForce",
    "Interlock", "Scattered Spider", "ShinyHunters", "Lapsus$", "Lazarus", "Kimsuky", "Volt Typhoon",
    "Salt Typhoon", "Silk Typhoon", "WaterPlum", "Gheist", "Lovely",
]
ACTOR_PATTERNS = [r"\bAPT ?\d+\b", r"\bUAT-\d+\b", r"\bPREY-\d+\b", r"\bUNC\d+\b", r"\bTA\d{3,}\b"]

# 国内記事の「本文 - 組織名」形式。末尾がこの語を含むなら組織名ではない。
_JA_TAIL_NG = re.compile(r"当局|注意喚起|悪用|修正|脆弱性|確認|公開|流出|対応|調査|判明|影響|「|」|件")
_JA_VICTIM_PATTERNS = [
    re.compile(r"^(?:[^\s、。]*?で)?(.{2,24}?)(?:に|で|が)(?:不正アクセス|身代金要求|ランサム|サイバー攻撃)"),
]
_EN_VICTIM_PATTERNS = [
    re.compile(r"^(?P<v>[A-Z][\w&.'’\- ]{1,60}?)\s+(?:suffers|discloses|confirms|says|probes|halts|hit by|"
               r"investigates|investigating|reports|notifies|warns customers|offers|data breach|breach)\b"),
    re.compile(r"^(?:Cyberattack|Ransomware attack|Cyber attack|Attack)\s+(?:disrupts|hits|on|cripples)\s+"
               r"(?P<v>.+?)(?:\s+(?:before|after|amid|in|as)\b|$)"),
    re.compile(r"^(?P<v>[A-Z][\w&.'’\- ]{1,40}?)\s+(?:Data|data) of\b"),
]
_EN_VICTIM_NG = re.compile(r"^(Hackers?|Attackers?|Researchers?|Police|CISA|Microsoft fixes|New|Fake|Malicious|"
                           r"Threat|Cybersecurity|Experts?|Limited|Reports?|Massive|Several|Multiple)\b", re.I)


def _any(patterns, text, flags=re.I):
    return any(re.search(p, text, flags) for p in patterns)


def classify_kind(title, text):
    """摘発系はタイトルだけで判定する（要約中の「過去にテイクダウンされた」等で誤判定しないため）。"""
    for kind, patterns in KIND_RULES:
        if _any(patterns, title if kind == "enforcement" else text):
            return kind
    return None


def attack_types(text):
    found = [t for t, patterns in ATTACK_TYPE_RULES.items() if _any(patterns, text)]
    # 「脆弱性の悪用」と書かれていない単なる脆弱性記事は vuln_exploit にしない
    if "vuln_exploit" in found and not re.search(r"悪用|exploit|zero-day|ゼロデイ|KEV|in the wild", text, re.I):
        found.remove("vuln_exploit")
    return found


def sectors(text):
    return [s for s, patterns in SECTOR_RULES.items() if _any(patterns, text)]


def countries(text, lang):
    found = [c for c, patterns in COUNTRY_RULES.items() if _any(patterns, text, 0)]
    return found


def actors(text):
    found = []
    for name in KNOWN_ACTORS:
        if re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", text):
            canonical = "Cl0p" if name == "Clop" else name
            if canonical not in found:
                found.append(canonical)
    for p in ACTOR_PATTERNS:
        for m in re.findall(p, text):
            if m not in found:
                found.append(m)
    return found


def victim(title, lang):
    title = title.strip()
    if lang == "ja":
        if " - " in title:
            tail = title.rsplit(" - ", 1)[1].strip()
            if 1 < len(tail) <= 20 and not _JA_TAIL_NG.search(tail):
                return tail
        for p in _JA_VICTIM_PATTERNS:
            m = p.search(title)
            if m:
                return m.group(1).strip("「」 ")
        return None
    if _EN_VICTIM_NG.search(title):
        return None
    for p in _EN_VICTIM_PATTERNS:
        m = p.search(title)
        if m:
            v = m.group("v").strip(" ,:")
            if 1 < len(v) and len(v.split()) <= 7:
                return v
    return None


def classify(title, summary, lang):
    """記事1件を分類して付加情報の dict を返す。サイバーセキュリティと無関係なら None。"""
    if re.match(r"^\s*PR[：:]", title):
        return None
    text = f"{title}\n{summary or ''}"
    kind = classify_kind(title, text)
    types = attack_types(text)
    if kind is None and not types:
        return None
    if kind is None:
        kind = "advisory"
    if kind == "advisory" and set(types) & {"ransomware", "data_breach", "unauthorized_access"}:
        kind = "incident"
    cs = countries(text, lang)
    if not cs and lang == "ja" and kind in ("incident", "mishandling"):
        cs = ["JP"]  # 国内メディアの被害記事で国名が無い場合は国内事案とみなす
    return {
        "kind": kind,
        "attack_types": types,
        "sectors": sectors(text) if kind in ("incident", "mishandling") else [],
        "countries": cs,
        "actors": actors(text),
        "victim": victim(title, lang) if kind in ("incident", "mishandling") else None,
    }
