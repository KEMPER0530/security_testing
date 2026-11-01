import { describe, it, expect } from "vitest";
import { severityLabel } from "./display";
describe("評価軸を独立して表示", () => {
  it("未評価をゼロと区別する", () => {
    expect(severityLabel(null)).toBe("未評価");
    expect(severityLabel(0)).toBe("なし");
  });
  it("CVSS境界で分類する", () => {
    for (const [value, label] of [
      [3.9, "低"],
      [4, "中"],
      [6.9, "中"],
      [7, "高"],
      [8.9, "高"],
      [9, "緊急"],
    ] as const)
      expect(severityLabel(value)).toBe(label);
  });
});
