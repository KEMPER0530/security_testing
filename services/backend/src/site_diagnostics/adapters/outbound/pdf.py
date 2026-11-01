"""Portable Japanese reports with an embedded, OFL-licensed font."""

from html import escape
from io import BytesIO
from pathlib import Path
from functools import lru_cache
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, KeepTogether
from site_diagnostics.domain.checks import CVSS_NOTICE


@lru_cache
def register_font():
    pdfmetrics.registerFont(
        TTFont("ZenKaku", str(Path(__file__).parent / "assets/ZenKakuGothicNew-Regular.ttf"))
    )


class ReportPdf:
    def render(self, job: dict, report: dict | None) -> bytes:
        register_font()
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=42,
            rightMargin=42,
            topMargin=48,
            bottomMargin=48,
            title="Security Testing 診断結果",
            author="Security Testing",
        )
        styles = {
            "title": ParagraphStyle(
                "title",
                fontName="ZenKaku",
                fontSize=23,
                leading=32,
                textColor=colors.HexColor("#123f39"),
                spaceAfter=18,
                wordWrap="CJK",
            ),
            "heading": ParagraphStyle(
                "heading",
                fontName="ZenKaku",
                fontSize=13,
                leading=20,
                textColor=colors.HexColor("#146653"),
                spaceAfter=9,
                wordWrap="CJK",
            ),
            "body": ParagraphStyle(
                "body",
                fontName="ZenKaku",
                fontSize=9,
                leading=15,
                spaceAfter=7,
                wordWrap="CJK",
                splitLongWords=True,
            ),
            "small": ParagraphStyle(
                "small",
                fontName="ZenKaku",
                fontSize=7.5,
                leading=12,
                spaceAfter=6,
                wordWrap="CJK",
                splitLongWords=True,
            ),
        }

        def p(text, style="body"):
            # Never interpret target-derived URLs, evidence or error messages as PDF markup.
            return Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style])

        def line(label, text, style="body"):
            return p(f"{label}：{text}", style)

        story = [p("SECURITY TESTING", "small"), p("Webサイト 診断結果", "title")]
        states = {"SUCCEEDED": "診断完了", "FAILED": "診断失敗", "CANCELLED": "キャンセル"}
        for label, value in [
            ("対象URL", job["url"]),
            ("状態", states[job["state"]]),
            ("受付日時（UTC）", job["created_at"]),
            ("終了日時（UTC）", job.get("finished_at", "記録なし")),
            ("診断ID", job["id"]),
            ("観測ルール版", job.get("rule_version", "記録なし")),
        ]:
            story.append(line(label, value))
        story.append(Spacer(1, 14))
        if report is None:
            story.extend(
                [
                    p("診断結果は確定していません", "heading"),
                    p(job.get("error") or "診断がキャンセルされました。"),
                    p(
                        "確認できなかった項目を「問題なし」と扱うことはありません。正常に完了した診断の履歴から結果をご確認ください。"
                    ),
                ]
            )
        else:
            summary = report["summary"]
            story.extend(
                [
                    p("結果の概要", "heading"),
                    line("設定改善候補", f"{summary.get('configuration_count', 0)}件"),
                    line(
                        "最高深刻度（設定観測による暫定評価）", summary.get("highest_severity") or "検出なし"
                    ),
                    line("CVSS参考評価", f"{summary.get('reference_assessed_count', 0)}件"),
                    line("CVSS採点対象外の改善候補", f"{summary.get('cvss_not_applicable_count', 0)}件"),
                    line("評価基準版", report.get("evaluation_policy_version", "記録なし")),
                    line("AI分析", "工事中（外部AIへの送信は行っていません）"),
                    p(CVSS_NOTICE),
                    p(
                        "保存済みの観測結果に評価基準を適用しています。PDF作成時にサイトを再診断していません。"
                    ),
                    p("診断範囲と限界", "heading"),
                    line("範囲", report["coverage"].get("scope", "単一URLの静的HTML")),
                    line("対象外", "、".join(report["coverage"].get("not_tested", []))),
                    p(
                        "未検出はサイト全体の安全性を保証するものではありません。設定の不足と、悪用が確認された脆弱性を区別して対応してください。"
                    ),
                ]
            )
            story.append(PageBreak())
            analysis = report.get("attack_analysis")
            if analysis:
                story.extend(
                    [
                        p("どこに注意が必要？", "title"),
                        p("設定に基づく攻撃シナリオの分析", "heading"),
                        p(analysis["notice"]),
                        p(analysis["scope"]),
                    ]
                )
                if not analysis["items"]:
                    story.append(
                        p(
                            "今回確認した設定には、この分析の対象となる改善候補がありませんでした。サイト全体の安全性を保証するものではありません。"
                        )
                    )
                for item in analysis["items"]:
                    story.append(
                        KeepTogether(
                            [
                                p(
                                    f"{item['title']} - 改善候補{item['finding_count']}件 / 注意度（暫定）：{item['severity']}",
                                    "heading",
                                ),
                                line("注意が必要な場所", item["location"]),
                                p(item["explanation"]),
                                line("起こり得る被害", item["possible_impact"]),
                                line("必要な追加条件", item["conditions"]),
                                line(
                                    "判断した根拠",
                                    " / ".join(f"{e['title']}：{e['observed']}" for e in item["evidence"]),
                                ),
                                line("まず取り組む対策", " / ".join(item["actions"])),
                                Spacer(1, 16),
                            ]
                        )
                    )
                story.append(
                    KeepTogether(
                        [
                            p("今回評価していない攻撃", "heading"),
                            *[line(item["title"], item["reason"]) for item in analysis["not_evaluated"]],
                            p(
                                "これらは問題なしという意味ではありません。必要な範囲に応じて追加診断をご検討ください。"
                            ),
                        ]
                    )
                )
                story.append(PageBreak())
            for i, f in enumerate(report["findings"]):
                cvss = f.get("cvss")
                score = (
                    f"{cvss['score']:.1f} / 10（{cvss['severity']}・参考評価）"
                    if cvss
                    else f.get("cvss_status", "未評価")
                )
                block = [
                    p(f"{i + 1:02d}  {f['title']}", "heading"),
                    line(
                        "判定",
                        f"{f['status']} ／ 深刻度（暫定）：{f.get('severity', '未評価')} ／ {f.get('priority', '要確認')}",
                    ),
                    line("どんなチェック？", f.get("explanation", "旧チェックの説明は記録されていません。")),
                    line("なぜ必要？", f.get("purpose", "詳細確認が必要です。")),
                    line("判定基準", f.get("criteria", "旧チェックの判定基準は記録されていません。")),
                    line("観測した根拠", f.get("evidence", "記録なし")),
                    line("改善方法", f.get("fix", "詳細確認が必要です。")),
                    line("CVSS v4.0", score),
                    p(f.get("cvss_reason", ""), "small"),
                ]
                if cvss:
                    block.extend(
                        [
                            line("採点時の仮定", cvss.get("scenario", "記録された評価根拠を参照"), "small"),
                            line("ベクトル", cvss["vector"], "small"),
                            line(
                                "各指標の根拠",
                                " / ".join(f"{k}={v}" for k, v in cvss.get("rationale", {}).items()),
                                "small",
                            ),
                        ]
                    )
                block.extend(
                    [
                        line(
                            "チェックの出典",
                            f.get("reference", "https://owasp.org/www-project-secure-headers/"),
                            "small",
                        ),
                        Spacer(1, 16),
                    ]
                )
                story.append(KeepTogether(block))

        def footer(canvas, document):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#d3e1dd"))
            canvas.line(42, 34, A4[0] - 42, 34)
            canvas.setFont("ZenKaku", 8)
            canvas.setFillColor(colors.HexColor("#55716a"))
            canvas.drawString(42, 21, "SECURITY TESTING  |  保存した診断履歴から出力")
            canvas.drawRightString(A4[0] - 42, 21, str(document.page))
            canvas.restoreState()

        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return buffer.getvalue()
