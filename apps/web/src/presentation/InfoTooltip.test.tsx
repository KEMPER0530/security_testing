// @vitest-environment jsdom
import React from "react";
import { it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { InfoTooltip } from "./InfoTooltip";
afterEach(cleanup);
it("タップとキーボードで説明を開き、Escapeや外側操作で閉じる", () => {
  render(
    <InfoTooltip
      label="CSPの説明"
      text="プログラムの出所を制限する設定です。"
    />,
  );
  const button = screen.getByRole("button", { name: "CSPの説明" });
  expect(screen.queryByRole("tooltip")).toBeNull();
  fireEvent.click(button);
  expect(screen.getByRole("tooltip").textContent).toContain("出所を制限");
  expect(button.getAttribute("aria-describedby")).toBe(
    screen.getByRole("tooltip").id,
  );
  fireEvent.keyDown(document, { key: "Escape" });
  expect(screen.queryByRole("tooltip")).toBeNull();
  fireEvent.focus(button);
  expect(screen.getByRole("tooltip")).toBeTruthy();
  fireEvent.pointerDown(document.body);
  expect(screen.queryByRole("tooltip")).toBeNull();
});
