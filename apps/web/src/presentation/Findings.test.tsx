// @vitest-environment jsdom
import React from "react";
import { it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { Findings } from "./Findings";

afterEach(cleanup);
it("質問票なしの結果に深刻度と優先度を表示し、CVSS未評価を区別する", () => {
  render(
    <Findings
      report={{
        summary: {
          highest_severity: "高",
          configuration_count: 1,
          unassessed_count: 1,
          cvss_severity_counts: {},
        },
        findings: [
          {
            rule_id: "HTTPS",
            title: "HTTPS利用",
            status: "問題を検出",
            severity: "高",
            priority: "P1 · 優先対応",
            cvss: null,
            evidence: "HTTP応答",
            fix: "HTTPSへ移行",
          },
        ],
        coverage: { scope: "単一URL", not_tested: ["認証後"] },
      }}
    />,
  );
  expect(screen.getAllByText("高").length).toBeGreaterThan(0);
  expect(screen.getAllByText("P1 · 優先対応").length).toBeGreaterThan(0);
  expect(screen.getAllByText("未評価").length).toBeGreaterThan(0);
  expect(screen.queryByText("システム重要度")).toBeNull();
});
it("以前に保存した深刻度なしのレポートも未評価として表示する", () => {
  render(
    <Findings
      report={{
        assessment: { confirmed_level: 3 },
        summary: {
          configuration_count: 1,
          unassessed_count: 1,
          cvss_severity_counts: {},
        },
        findings: [
          {
            rule_id: "CSP",
            title: "CSP",
            status: "問題を検出",
            cvss: null,
            priority: "確認待ち",
          },
        ],
        coverage: { scope: "単一URL", not_tested: [] },
      }}
    />,
  );
  expect(screen.getAllByText("未評価").length).toBeGreaterThan(0);
  expect(screen.queryByText("システム重要度")).toBeNull();
});
