import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

test.skip(
  process.env.E2E_REPORTS !== "1",
  "新規のローカル検証データだけでPDFと削除を明示検証する",
);
test("診断履歴からPDFを取得し、説明をタップで読み、作成した履歴と対象を削除する", async ({
  page,
}) => {
  test.setTimeout(360000);
  await page.goto("/");
  await page.getByRole("button", { name: "ログインして始める →" }).click();
  await page.getByLabel("Username or email").fill("developer");
  await page
    .getByLabel("Password", { exact: true })
    .fill("local-development-only");
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "診断ワークスペース" }),
  ).toBeVisible();
  // Register our own fixture record; never delete pre-existing records.
  await page
    .getByLabel("診断する公開サイトのURL")
    .fill("http://fixture.security-testing.test/");
  const [registration] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/targets"),
      { timeout: 60000 },
    ),
    page.getByRole("button", { name: "登録 ＋" }).click(),
  ]);
  expect(registration.status(), await registration.text()).toBe(201);
  const target = await registration.json();
  const selected = page.locator(`[data-target-id="${target.sk}"]`);
  await expect(selected).toHaveAttribute("aria-pressed", "true");
  const [started] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/scans"),
    ),
    page.getByRole("button", { name: "診断を開始 →" }).click(),
  ]);
  expect(started.status(), await started.text()).toBe(202);
  const job = await started.json();
  const row = page.locator(`[data-history-id="${job.id}"]`);
  await expect(page.getByTestId("diagnosis-report")).toBeVisible({
    timeout: 150000,
  });
  await expect(row.getByRole("button", { name: "PDF ↓" })).toBeEnabled();
  await expect(
    page.getByRole("heading", { name: "どこに注意が必要？" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "AI分析を実行（準備中）" }),
  ).toBeDisabled();
  await expect(page.getByText("工事中", { exact: true })).toBeVisible();
  const [response, download] = await Promise.all([
    page.waitForResponse((r) =>
      r.url().endsWith(`/v1/scans/${job.id}/report.pdf`),
    ),
    page.waitForEvent("download"),
    row.getByRole("button", { name: "PDF ↓" }).click(),
  ]);
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toBe("application/pdf");
  const file = resolve("../../.build/local-history-report.pdf");
  await download.saveAs(file);
  expect((await readFile(file)).subarray(0, 5).toString()).toBe("%PDF-");
  await page.setViewportSize({ width: 390, height: 844 });
  const help = page.getByRole("button", {
    name: "CSPの設定の説明",
    exact: true,
  });
  await help.click();
  await expect(page.getByRole("tooltip")).toContainText("プログラムの出所");
  const box = await page.getByRole("tooltip").boundingBox();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  await page.screenshot({
    path: resolve("../../.build/reports-mobile-tooltip.png"),
  });
  await page.keyboard.press("Escape");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await row.scrollIntoViewIfNeeded();
  await page.screenshot({
    path: resolve("../../.build/reports-mobile-history.png"),
  });
  page.on("dialog", (dialog) => dialog.accept());
  const [removed] = await Promise.all([
    page.waitForResponse(
      (r) =>
        r.request().method() === "DELETE" &&
        r.url().endsWith(`/v1/scans/${job.id}`),
    ),
    row.getByRole("button", { name: "診断履歴を削除" }).click(),
  ]);
  expect(removed.status()).toBe(204);
  await expect(row).toHaveCount(0);
  await expect(selected).toBeVisible();
  const [removedTarget] = await Promise.all([
    page.waitForResponse(
      (r) =>
        r.request().method() === "DELETE" &&
        r.url().endsWith(`/v1/targets/${target.sk.replace("TARGET#", "")}`),
    ),
    selected
      .locator("..")
      .getByRole("button", { name: "診断対象を削除" })
      .click(),
  ]);
  expect(removedTarget.status()).toBe(204);
  await expect(selected).toHaveCount(0);
  console.log(
    "LocalStack: authenticated PDF bytes, mobile tooltip, history deletion and target deletion passed (only newly-created fixture records removed).",
  );
});
