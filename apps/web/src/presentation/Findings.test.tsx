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

it.each([
  [
    "network",
    "TCPポートの接続結果",
    {
      rule_id: "PORT_443",
      title: "TCP 443の接続",
      details: { port: 443, connection: "open" },
    },
    "TCP 443 / TCP接続可",
  ],
  [
    "pentest",
    "HTTPの限定検証",
    {
      rule_id: "TRACE",
      title: "TRACE応答",
      details: { method: "TRACE", http_status: 405 },
    },
    "TRACE / HTTP 405",
  ],
  [
    "host",
    "Inspectorが検出した既知の脆弱性",
    {
      rule_id: "AWS_INSPECTOR_abcdef1234567890abcdef12_0",
      kind: "vulnerability",
      title: "既知の脆弱性",
      details: {
        resource: "i-0123456789abcdef0",
        vulnerability_id: "CVE-2025-0001",
      },
    },
    "i-0123456789abcdef0 / CVE-2025-0001",
  ],
  [
    "cloud",
    "S3の公開防止・暗号化",
    {
      rule_id: "AWS_S3_PUBLIC_0",
      title: "S3公開防止",
      details: { check: "s3", resource: "example-bucket" },
    },
    "example-bucket",
  ],
])(
  "%sの保存結果は固有のグループと観測値を表示する",
  (profile, heading, finding, context) => {
    render(
      <Findings
        report={{
          plan: { profile },
          coverage: { profile, scope: "選択範囲のみ", not_tested: [] },
          summary: { configuration_count: 0, cvss_severity_counts: {} },
          findings: [
            {
              status: "確認不能",
              severity: "未評価",
              evidence: "限定検査",
              ...finding,
            },
          ],
          ipa_checklist: [],
        }}
      />,
    );
    expect(
      screen.getByRole("heading", { name: new RegExp(heading) }),
    ).toBeTruthy();
    expect(screen.getAllByText(context).length).toBeGreaterThan(0);
    if (profile === "host" || profile === "cloud")
      expect(screen.queryByText("IPAの対策項目と確認できた範囲")).toBeNull();
  },
);
it("別種類の結果を渡されても選択中の種類として表示しない", () => {
  render(
    <Findings
      expectedProfile="network"
      report={{
        plan: { profile: "web" },
        coverage: { profile: "web" },
        findings: [],
      }}
    />,
  );
  expect(screen.getByRole("alert").textContent).toContain(
    "診断種類が一致しない",
  );
  expect(screen.queryByTestId("diagnosis-report")).toBeNull();
});
