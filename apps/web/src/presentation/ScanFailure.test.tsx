// @vitest-environment jsdom
import React from "react";
import { it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { ScanFailure } from "./ScanFailure";

afterEach(cleanup);
it("以前の一括エラーも取得失敗と原因未特定を説明する", () => {
  render(
    <ScanFailure message="接続・DNS・TLS検証に失敗しました（証明書検証は有効）" />,
  );
  const message = screen.getByRole("alert").textContent;
  expect(message).toContain("診断先ページを取得できませんでした");
  expect(message).toContain("詳細がありません");
  expect(message).toContain("安全性は判定していません");
});
it("証明書エラーでは期限などを確認する理由を表示する", () => {
  render(
    <ScanFailure
      code="TLS_CERTIFICATE"
      message="有効期限・対象ドメイン・中間証明書を確認してください。"
    />,
  );
  expect(screen.getByRole("alert").textContent).toContain(
    "HTTPS証明書を検証できませんでした",
  );
  expect(screen.getByRole("alert").textContent).toContain("有効期限");
});
it("DNSエラーを証明書エラーと混同しない", () => {
  render(
    <ScanFailure
      code="DNS_FAILURE"
      message="URLとDNS設定を確認してください。"
    />,
  );
  const message = screen.getByRole("alert").textContent;
  expect(message).toContain("IPアドレスを取得できませんでした");
  expect(message).not.toContain("証明書を検証");
});
