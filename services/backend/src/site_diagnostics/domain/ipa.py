"""Our coverage map, not an IPA certification or a copy of the full IPA checklist."""

IPA_SOURCE = "https://www.ipa.go.jp/security/vuln/websecurity/ug65p900000196e2-att/000017316.pdf"
IPA_EDITION = "安全なウェブサイトの作り方 改訂第7版（2021年3月）"
IPA_NOTICE = "IPA資料を参照して当アプリの確認範囲を整理した独自の対応表です。IPAの認証・完全準拠を示すものではありません。関連ヘッダーの確認だけでは、プログラムの根本的な対策を確認したことにはなりません。"

# Section and printed page numbers refer to the supplied edition; PDF page is printed page + 2.
SECTIONS = [
    ("1.1", 6, "データベースに不正な命令を渡さない", [], "入力処理・SQLの組み立て方を検証する"),
    ("1.2", 10, "サーバーの命令実行を入力から守る", [], "外部入力を使うコマンド実行を検証する"),
    ("1.3", 13, "許可しないファイルを読ませない", [], "ファイル指定・公開範囲を検証する"),
    ("1.4", 16, "ログイン状態を適切に管理する", ["COOKIE"], "IDの推測困難性・更新・失効は別途検証する"),
    (
        "1.5",
        22,
        "ページに不正なプログラムを混ぜさせない",
        ["CSP", "NOSNIFF", "TRACE"],
        "出力時の無害化・入力処理・実行可否を検証する",
    ),
    ("1.6", 30, "本人の意図しない操作を防ぐ", [], "操作ごとの本人確認・送信元確認を検証する"),
    ("1.7", 34, "応答ヘッダーへの不正な挿入を防ぐ", [], "入力の改行やヘッダー生成処理を検証する"),
    ("1.8", 38, "メールの宛先や件名を不正に変えさせない", [], "メール送信APIと入力の扱いを検証する"),
    (
        "1.9",
        41,
        "別画面に重ねた不正なクリックを防ぐ",
        ["FRAME"],
        "埋込先の許可内容・実際の画面動作を検証する",
    ),
    ("1.10", 44, "メモリーを扱うプログラムの欠陥に備える", [], "対象ソフトウェアと修正版の適用を検証する"),
    ("1.11", 46, "利用者ごとの閲覧・操作権限を守る", [], "ログイン後・別利用者・管理者の権限を検証する"),
    (
        "2.1",
        48,
        "公開サーバーと不要な情報を管理する",
        ["DISCLOSURE"],
        "OS・ソフトウェア・公開ファイル・サービスを検証する",
    ),
    ("2.2", 49, "名前解決の設定を適切に管理する", ["DNS"], "DNS運用・権限・公開設定を別途検証する"),
    (
        "2.3",
        51,
        "通信の盗み見に備える",
        ["HTTPS", "TLS", "HSTS", "MIXED", "REDIRECT"],
        "全ページ・ログイン後・重要情報の通信を検証する",
    ),
]


def ipa_checklist(findings: list[dict]) -> list[dict]:
    observed = {f["rule_id"]: f for f in findings}
    rows = []
    for section, page, title, codes, additional in SECTIONS:
        related = [observed[c] for c in codes if c in observed]
        completed = [f for f in related if f["status"] in ("問題を検出", "問題を検出せず")]
        rows.append(
            {
                "section": section,
                "page": page,
                "pdf_page": page + 2,
                "title": title,
                "coverage": "関連設定のみ観測" if completed else "未実施",
                "observed_checks": [f["title"] for f in completed],
                "detected_count": sum(f["status"] == "問題を検出" for f in completed),
                "additional_verification": additional,
                "source": f"{IPA_SOURCE}#page={page + 2}",
            }
        )
    return rows
