"""Explain potential attack paths from observations, without predicting an attack."""

ANALYSIS_VERSION = "2026-11-02.1"
NOTICE = (
    "公開ページで確認した設定をもとに、追加の条件が重なった場合に考えられる攻撃を整理しています。"
    "攻撃の発生・成功・被害や、攻撃される確率を示すものではありません。"
    "件数は改善候補となったチェック項目の数です。"
)
GROUPS = [
    {
        "id": "communication",
        "title": "通信の盗み見・書き換え",
        "rules": ["TLS", "HTTPS", "HSTS", "MIXED", "REDIRECT"],
        "location": "サイトと利用者の間の通信経路、HTTPで読み込む画像・プログラムなど",
        "explanation": "利用者とサイトの間に入り込んだ第三者が、暗号化されていない通信を読んだり、届く内容を変えたりする攻撃です。",
        "possible_impact": "通信に個人情報や操作内容が含まれる場合、情報が知られたり、表示や操作が変えられたりする可能性があります。",
        "conditions": "攻撃者が通信経路に入れることや、保護されない通信をブラウザーが実際に利用することが必要です。今回、その成立は検証していません。",
    },
    {
        "id": "script",
        "title": "不正なプログラムの実行（XSSなど）",
        "rules": ["CSP", "NOSNIFF"],
        "location": "ブラウザーに表示するページと、そこで読み込むプログラム・ファイル",
        "explanation": "本来のページに不正なプログラムを混ぜて、閲覧した利用者のブラウザーで動かす攻撃です。",
        "possible_impact": "画面に偽の入力欄を出す、閲覧できる情報を盗む、利用者になりすまして操作する、といった被害につながる可能性があります。",
        "conditions": "不正な内容をページやファイルへ混入できる別の欠陥が必要です。入力欄の欠陥やプログラムの実行は今回検証していません。",
    },
    {
        "id": "clickjacking",
        "title": "だましてボタンを押させる攻撃",
        "rules": ["FRAME"],
        "location": "別のサイトの中に埋め込まれる可能性があるページ",
        "explanation": "別サイトの画面に本物のページを重ね、利用者が気づかないうちに本物のボタンを押すよう誘導する攻撃です。クリックジャッキングと呼ばれます。",
        "possible_impact": "ログイン中の利用者が、意図しない設定変更や操作を行う可能性があります。",
        "conditions": "埋め込みが実際に許されること、変更操作が存在すること、利用者が誘導された画面を操作することが必要です。操作の存在や攻撃の成功は未検証です。",
    },
    {
        "id": "session",
        "title": "ログイン状態の悪用・なりすまし",
        "rules": ["COOKIE"],
        "location": "ブラウザーに保存するCookie（ログイン状態などを覚える情報）の保護設定",
        "explanation": "ログイン状態を示す情報を盗む、または利用者のブラウザーに不正な操作をさせることで、本人になりすます攻撃です。",
        "possible_impact": "Cookieがログイン用の場合、本人だけが見られる情報の閲覧や操作につながる可能性があります。",
        "conditions": "指摘されたCookieがログインに使われることや、盗み見・別のプログラム実行などの経路が必要です。Cookieの用途や値は今回確認・保存していません。",
    },
    {
        "id": "reconnaissance",
        "title": "攻撃準備に使われる識別情報の公開",
        "rules": ["DISCLOSURE"],
        "location": "サイトが返す応答の付帯情報（サーバー識別ヘッダー）",
        "explanation": "サーバー製品を推測できる情報が、攻撃者の事前調査に使われる可能性があります。これは攻撃そのものの検出ではありません。",
        "possible_impact": "ほかに製品の欠陥がある場合に、攻撃手段を探すヒントになります。識別情報の公開だけで直接の侵入や被害は確認できません。",
        "conditions": "製品や版の特定、既知の欠陥の存在、実際の構成との一致などが必要です。今回はヘッダーの有無だけを観測しています。",
    },
]
NOT_EVALUATED = [
    {
        "title": "データベースへの不正命令（SQLインジェクション）",
        "reason": "入力内容がデータベースでどう処理されるかを検証していません。",
    },
    {
        "title": "大量アクセスによるサービス停止（DDoS）",
        "reason": "負荷試験や基盤の防御設定の確認を行っていません。",
    },
    {
        "title": "ログイン突破・権限の不正利用",
        "reason": "ログイン後の画面、利用者の権限、業務上の操作を検証していません。",
    },
]


def analyze(findings: list[dict], target_url: str | None = None) -> dict:
    detected = {f["rule_id"]: f for f in findings if f["status"] == "問題を検出"}
    ranks = {"緊急": 0, "高": 1, "中": 2, "低": 3, "未評価": 4}
    items = []
    for group in GROUPS:
        matches = [detected[code] for code in group["rules"] if code in detected]
        if not matches:
            continue
        rating = min((f.get("severity", "未評価") for f in matches), key=lambda s: ranks.get(s, 4))
        items.append(
            {
                **{k: v for k, v in group.items() if k != "rules"},
                "severity": rating,
                "finding_count": len(matches),
                "evidence": [
                    {"rule_id": f["rule_id"], "title": f["title"], "observed": f.get("evidence", "記録なし")}
                    for f in matches
                ],
                "actions": list(dict.fromkeys(f.get("fix", "詳細な検証を依頼する") for f in matches)),
            }
        )
    return {
        "version": ANALYSIS_VERSION,
        "notice": NOTICE,
        "scope": "登録した単一URLの静的HTMLと応答設定。サイト全体や内部構成の分析ではありません。",
        "target_url": target_url or next((f["target"] for f in findings if f.get("target")), None),
        "total_findings": len(detected),
        "items": sorted(items, key=lambda i: ranks.get(i["severity"], 4)),
        "not_evaluated": NOT_EVALUATED,
    }
