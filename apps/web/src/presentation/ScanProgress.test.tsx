// @vitest-environment jsdom
import React from "react";
import { it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { ScanProgress } from "./ScanProgress";
afterEach(cleanup);
it("実行中は実測していないパーセンテージを表示せず非同期処理を案内する", () => {
  const { rerender } = render(
    <ScanProgress state="QUEUED" url="https://example.test/" />,
  );
  expect(
    screen.getByRole("heading", { name: "受付済み・順番待ち" }),
  ).toBeTruthy();
  expect(screen.getByRole("progressbar").hasAttribute("aria-valuenow")).toBe(
    false,
  );
  expect(screen.getByTestId("scan-progress").getAttribute("aria-busy")).toBe(
    "true",
  );
  expect(screen.getByText(/画面を離れても診断は続き/)).toBeTruthy();
  rerender(<ScanProgress state="SUCCEEDED" url="https://example.test/" />);
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect(screen.getByTestId("scan-progress").getAttribute("aria-busy")).toBe(
    "false",
  );
});
