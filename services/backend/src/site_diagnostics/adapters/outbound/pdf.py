"""Table-based diagnostic reports with Japanese text and explicit observation limits."""

from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from html import escape
from io import BytesIO
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle,
)
from site_diagnostics.domain.checks import CVSS_NOTICE
from site_diagnostics.domain.plans import PROFILES
from site_diagnostics.domain.ipa import IPA_EDITION, IPA_NOTICE, IPA_SOURCE, ipa_checklist

GREEN = colors.HexColor("#123f39")
BORDER = colors.HexColor("#cfddd7")
PALE = colors.HexColor("#edf5f1")
STATUS = {
    "問題を検出": "要改善",
    "問題を検出せず": "指摘なし※",
    "対象外": "対象外",
    "未実施": "未実施",
    "確認不能": "要確認",
}


@lru_cache
def register_font():
    pdfmetrics.registerFont(
        TTFont("ZenKaku", str(Path(__file__).parent / "assets/ZenKakuGothicNew-Regular.ttf"))
    )


def readable_time(value):
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if d.tzinfo is None:
            return value
        return d.astimezone(timezone(timedelta(hours=9))).strftime("%Y/%m/%d %H:%M:%S（日本時間）")
    except (TypeError, ValueError, AttributeError):
        return value or "記録なし"


def cvss_label(f):
    value = f.get("cvss")
    if not value:
        return f.get("cvss_status", "未評価")
    kind = "参考" if value.get("assessment") == "scenario_reference" else "提供元評価"
    return f"{float(value['score']):.1f} / {value.get('severity', '未評価')}（{kind}・CVSS {value.get('version', '記録なし')}）"


class ReportPdf:
    def render(self, job: dict, report: dict | None) -> bytes:
        register_font()
        buffer = BytesIO()
        width = A4[0] - 72
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=42,
            bottomMargin=42,
            title="Security Testing 診断レポート",
            author="Security Testing",
        )
        styles = {
            "title": ParagraphStyle(
                "title",
                fontName="ZenKaku",
                fontSize=20,
                leading=28,
                textColor=GREEN,
                spaceAfter=10,
                wordWrap="CJK",
            ),
            "heading": ParagraphStyle(
                "heading",
                fontName="ZenKaku",
                fontSize=12,
                leading=19,
                textColor=GREEN,
                spaceBefore=9,
                spaceAfter=8,
                wordWrap="CJK",
            ),
            "body": ParagraphStyle(
                "body", fontName="ZenKaku", fontSize=9, leading=14, spaceAfter=4, wordWrap="CJK"
            ),
            "small": ParagraphStyle(
                "small", fontName="ZenKaku", fontSize=8, leading=12, spaceAfter=3, wordWrap="CJK"
            ),
            "tiny": ParagraphStyle(
                "tiny", fontName="ZenKaku", fontSize=7, leading=10, spaceAfter=2, wordWrap="CJK"
            ),
            "header": ParagraphStyle(
                "header", fontName="ZenKaku", fontSize=8.5, leading=13, textColor=colors.white, wordWrap="CJK"
            ),
        }

        def p(value, style="body"):
            return Paragraph(escape(str(value or "")).replace("\n", "<br/>"), styles[style])

        def table(rows, widths, header=True, font="small", extra=(), padding=6):
            data = [
                [
                    cell
                    if isinstance(cell, (Paragraph, list))
                    else p(cell, "header" if header and i == 0 else font)
                    for cell in row
                ]
                for i, row in enumerate(rows)
            ]
            result = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0, splitInRow=1)
            rules = [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.45, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), padding),
                ("BOTTOMPADDING", (0, 0), (-1, -1), padding),
            ]
            if header:
                rules += [
                    ("BACKGROUND", (0, 0), (-1, 0), GREEN),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8faf9")]),
                ]
            result.setStyle(TableStyle([*rules, *extra]))
            return result

        def label_rows(rows):
            return table(rows, [84, width - 84], False, extra=[("BACKGROUND", (0, 0), (0, -1), PALE)])

        plan = job.get("plan") or (report or {}).get("plan") or {}
        profile = plan.get("profile") or (report or {}).get("coverage", {}).get("profile", "web")
        profile_info = PROFILES.get(profile, {})
        show_ipa = profile in ("web", "pentest")
        detail_section = 4 if show_ipa else 3
        states = {"SUCCEEDED": "診断完了", "FAILED": "診断失敗", "CANCELLED": "キャンセル"}
        story = [p("SECURITY TESTING / DIAGNOSTIC REPORT", "tiny"), p("診断レポート", "title")]
        story.append(
            label_rows(
                [
                    ("診断の種類", profile_info.get("title", "記録なし")),
                    ("登録URL" if profile in ("host", "cloud") else "対象URL", job["url"]),
                    (
                        "実行した検査",
                        "、".join(
                            profile_info.get("checks", {}).get(k, k)
                            for k in (
                                plan.get("checks")
                                or (report or {}).get("coverage", {}).get("checks")
                                or (["headers"] if profile == "web" else [])
                            )
                        )
                        or "記録なし",
                    ),
                    ("実行結果", states[job["state"]] + "（保存結果から出力・再診断なし）"),
                    (
                        "受付 / 終了",
                        f"{readable_time(job['created_at'])}\n{readable_time(job.get('finished_at'))}",
                    ),
                    ("診断ID", job["id"]),
                ]
            )
        )
        if report is None:
            story += [
                p("検査を完了できませんでした", "heading"),
                label_rows(
                    [
                        ("理由", job.get("error") or "診断がキャンセルされました。"),
                        (
                            "診断結果",
                            "未実施・確認不能。確認できなかった項目を「問題なし」として扱うことはありません。",
                        ),
                        ("次の対応", "接続先や設定を確認し、新しい診断を完了させてください。"),
                    ]
                ),
            ]
        else:
            findings = report["findings"]
            counts = Counter(f["status"] for f in findings)
            story += [
                p("1. 結果の要約", "heading"),
                table(
                    [
                        ["要改善", "指摘なし※", "未実施・要確認", "対象外"],
                        [
                            f"{counts['問題を検出']}件",
                            f"{counts['問題を検出せず']}件",
                            f"{counts['未実施'] + counts['確認不能']}件",
                            f"{counts['対象外']}件",
                        ],
                    ],
                    [width / 4] * 4,
                ),
                Spacer(1, 7),
                p(
                    "※「指摘なし」は今回確認した項目の範囲内です。サイト全体の安全性や、IPAの全対策への適合を示しません。",
                    "small",
                ),
                p(
                    f"確認範囲：{report['coverage'].get('scope', '記録なし')}。未確認：{'、'.join(report['coverage'].get('not_tested', []))}",
                    "small",
                ),
                p("2. 診断結果一覧", "heading"),
            ]
            rows: list[list] = [["診断項目", "判定", "深刻度", "CVSS"]]
            for f in findings:
                rows.append(
                    [
                        f["title"],
                        STATUS.get(f["status"], f["status"]),
                        f"{f.get('severity', '未評価')}（暫定）",
                        cvss_label(f),
                    ]
                )
            story += [
                table(rows, [158, 78, 86, width - 322]),
                Spacer(1, 6),
                p(
                    CVSS_NOTICE
                    if any((f.get("cvss") or {}).get("assessment") == "scenario_reference" for f in findings)
                    else "CVSSは具体的な既知脆弱性の数値を提供元評価として掲載します。設定観測だけで悪用条件が分からない項目は適用外、確認できなかった項目は未実施と区別します。",
                    "small",
                ),
            ]
            if profile == "network" and plan.get("ports"):
                story.append(label_rows([("対象TCPポート", ", ".join(str(port) for port in plan["ports"]))]))
            if profile in ("host", "cloud"):
                scope_rows = [
                    ("リージョン", plan.get("region") or report["coverage"].get("region", "記録なし"))
                ]
                for kind, values in (
                    plan.get("resources") or report["coverage"].get("resources", {})
                ).items():
                    scope_rows.append(
                        (
                            {
                                "instances": "対象EC2",
                                "buckets": "対象S3",
                                "security_groups": "対象SG",
                                "trails": "対象CloudTrail",
                            }.get(kind, kind),
                            "\n".join(values),
                        )
                    )
                story.append(label_rows(scope_rows))
            if show_ipa:
                story += [
                    PageBreak(),
                    p("3. IPA対策との対応関係", "title"),
                    p(IPA_EDITION, "small"),
                    p(IPA_NOTICE, "small"),
                ]
                rows = [["IPA節 / 頁", "確認すること（独自の要約）", "今回の確認", "追加で必要な確認"]]
                for item in report.get("ipa_checklist") or ipa_checklist(findings):
                    rows.append(
                        [
                            f"{item['section']} / p.{item['page']}",
                            item["title"],
                            item["coverage"]
                            + (f"\n関連指摘 {item['detected_count']}件" if item["observed_checks"] else ""),
                            item["additional_verification"],
                        ]
                    )
                story += [
                    table(rows, [57, 148, 98, width - 303]),
                    Spacer(1, 6),
                    p(
                        "章・ページはIPA資料の冊子記載ページです。関連設定が観測できても、各章の根本的な対策全体は未検証です。",
                        "tiny",
                    ),
                    p("参照元：" + IPA_SOURCE, "tiny"),
                ]
            story += [PageBreak(), p(f"{detail_section}. 項目別の分析", "title")]
            for f in findings:
                cvss = f.get("cvss")
                rows = [
                    [p(f["title"], "header"), ""],
                    [
                        "判定 / 優先度",
                        f"{STATUS.get(f['status'], f['status'])} / {f.get('priority', '要確認')}",
                    ],
                    ["項目の説明", f"{f.get('explanation', '説明の記録なし')}\n{f.get('purpose', '')}"],
                    [
                        "判定基準 / 根拠",
                        f"{f.get('criteria', '判定基準の記録なし')}\n観測：{f.get('evidence', '記録なし')}",
                    ],
                    ["改善方法", f.get("fix", "追加の調査が必要です。")],
                    ["CVSS", cvss_label(f) + "\n" + f.get("cvss_reason", "")],
                ]
                details = f.get("details") or {}
                observation = []
                if details.get("resource"):
                    observation.append("対象：" + str(details["resource"]))
                if details.get("port"):
                    observation.append("TCP " + str(details["port"]))
                if details.get("connection"):
                    observation.append(
                        {"open": "TCP接続可", "refused": "接続拒否", "unknown": "確認不能"}.get(
                            details["connection"], "確認不能"
                        )
                    )
                if details.get("method"):
                    observation.append(str(details["method"]))
                if details.get("http_status"):
                    observation.append("HTTP " + str(details["http_status"]))
                if observation:
                    rows.insert(2, ["検査固有の観測", " / ".join(observation)])
                if cvss:
                    rows.extend(
                        [
                            ["採点時の仮定", cvss.get("scenario") or "提供元が示した条件に基づく評価。"],
                            [
                                "ベクトル / 指標",
                                [
                                    p(cvss.get("vector", "記録なし"), "tiny"),
                                    p(
                                        " / ".join(f"{k}：{v}" for k, v in cvss.get("rationale", {}).items()),
                                        "tiny",
                                    ),
                                ],
                            ],
                        ]
                    )
                rows.append(["参考資料", f.get("reference", "https://owasp.org/www-project-secure-headers/")])
                story.append(
                    table(
                        rows,
                        [84, width - 84],
                        extra=[
                            ("SPAN", (0, 0), (-1, 0)),
                            ("NOSPLIT", (0, 0), (-1, 3)),
                            ("NOSPLIT", (0, -2), (-1, -1)),
                            ("BACKGROUND", (0, 1), (0, -1), PALE),
                        ],
                        padding=5,
                    )
                )
                story.append(Spacer(1, 10))
            analysis = report.get("attack_analysis")
            if analysis:
                story += [
                    PageBreak(),
                    p(f"{detail_section + 1}. どこに注意が必要？", "title"),
                    p(analysis["notice"], "small"),
                ]
                rows = [["種類 / 注意箇所", "起こり得る被害と必要な追加条件", "まず取り組む対策"]]
                for item in analysis["items"]:
                    rows.append(
                        [
                            f"{item['title']}\n{item['location']}\n改善候補 {item['finding_count']}件",
                            f"{item['possible_impact']}\n条件：{item['conditions']}",
                            "\n".join(item["actions"]),
                        ]
                    )
                if len(rows) > 1:
                    story.append(table(rows, [145, 228, width - 373]))
                else:
                    story.append(
                        p(
                            "今回の観測には分析対象となる改善候補がありませんでした。サイト全体の安全性を保証するものではありません。"
                        )
                    )
                story += [
                    p("今回評価していない攻撃", "heading"),
                    table(
                        [
                            ["種類", "確認していないこと"],
                            *[[i["title"], i["reason"]] for i in analysis["not_evaluated"]],
                        ],
                        [180, width - 180],
                    ),
                ]
            story += [
                Spacer(1, 12),
                p("報告書の情報", "heading"),
                label_rows(
                    [
                        ("観測ルール版", job.get("rule_version", "記録なし")),
                        ("評価基準版", report.get("evaluation_policy_version", "記録なし")),
                        ("AI分析", "工事中（外部AIへの送信は行っていません）"),
                    ]
                ),
            ]

        def footer(canvas, document):
            canvas.saveState()
            canvas.setStrokeColor(BORDER)
            canvas.line(36, 29, A4[0] - 36, 29)
            canvas.setFont("ZenKaku", 7)
            canvas.setFillColor(colors.HexColor("#55716a"))
            canvas.drawString(36, 17, "SECURITY TESTING | 保存した診断履歴から出力")
            canvas.drawRightString(A4[0] - 36, 17, str(document.page))
            canvas.restoreState()

        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return buffer.getvalue()
