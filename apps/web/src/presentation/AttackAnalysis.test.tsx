// @vitest-environment jsdom
import React from "react";
import { it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { AttackAnalysis, AiAnalysisPending } from "./AttackAnalysis";
afterEach(cleanup);
it("場所・攻撃の内訳・被害・根拠・追加条件を非エンジニア向けに区別する", () => {
  render(
    <AttackAnalysis
      analysis={{
        notice: "攻撃される確率ではありません。",
        scope: "単一URLの設定",
        target_url: "https://example.com/",
        items: [
          {
            id: "script",
            title: "不正なプログラムの実行",
            location: "ブラウザーで表示するページ",
            explanation: "不正なプログラムを混ぜる攻撃です。",
            possible_impact: "表示内容の改ざん",
            conditions: "混入できる別の欠陥が必要です。",
            severity: "中",
            finding_count: 1,
            evidence: [{ rule_id: "CSP", title: "CSP", observed: "制約なし" }],
            actions: ["実行元を制限する"],
          },
        ],
        not_evaluated: [{ title: "DDoS", reason: "負荷試験をしていません" }],
      }}
    />,
  );
  expect(screen.getByText("ブラウザーで表示するページ")).toBeTruthy();
  expect(screen.getByText("1件")).toBeTruthy();
  expect(screen.getByText("混入できる別の欠陥が必要です。")).toBeTruthy();
  expect(screen.getByText("負荷試験をしていません")).toBeTruthy();
});
it("AI分析は工事中で実行できない", () => {
  render(<AiAnalysisPending />);
  expect(screen.getByText("工事中")).toBeTruthy();
  expect(
    screen
      .getByRole("button", { name: "AI分析を実行（準備中）" })
      .hasAttribute("disabled"),
  ).toBe(true);
  expect(
    screen.getByText(/外部AIへ診断データを送ることはありません/),
  ).toBeTruthy();
});
