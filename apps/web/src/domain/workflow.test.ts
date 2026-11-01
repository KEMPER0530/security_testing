import { describe, it, expect } from "vitest";
import { isActive, nextAction, stateLabel } from "./workflow";
describe("診断開始の条件と実行状態", () => {
  it("公開サイトの登録後は事前設定なしで診断できる", () => {
    expect(nextAction(false)).toContain("URLを登録");
    expect(nextAction(true)).toContain("準備ができました");
  });
  it("進行中と終了を区別する", () => {
    for (const state of ["QUEUED", "RUNNING", "CANCEL_REQUESTED"])
      expect(isActive(state)).toBe(true);
    for (const state of ["SUCCEEDED", "FAILED", "CANCELLED", undefined])
      expect(isActive(state)).toBe(false);
    expect(stateLabel("QUEUED")).toContain("順番待ち");
  });
});
