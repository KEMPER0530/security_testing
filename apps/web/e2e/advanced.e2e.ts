import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

let nextHostRun = 0;

test.skip(
  process.env.E2E_ADVANCED !== "1",
  "制御下fixtureとLocalStackで追加診断を明示検証する",
);
test("手動ネットワーク検査、履歴PDF、AWS接続準備とモバイル表示", async ({
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
  await page
    .getByLabel("診断する公開サイトのURL")
    .fill("http://fixture.security-testing.test/");
  const [created] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/targets"),
      { timeout: 60000 },
    ),
    page.getByRole("button", { name: "登録 ＋" }).click(),
  ]);
  expect(created.status(), await created.text()).toBe(201);
  const target = await created.json();
  const selected = page.locator(`[data-target-id="${target.sk}"]`);
  await expect(selected).toHaveAttribute("aria-pressed", "true");
  await page
    .getByText("検査内容を選んで手動実行（ネットワーク・AWS・限定Web検証）")
    .click();
  await expect(page.getByLabel("診断の種類")).toBeVisible();
  await page.getByLabel("Web通信とTLS証明書").uncheck();
  await page.getByLabel("443", { exact: true }).uncheck();
  await page.getByLabel("80", { exact: true }).check();
  const start = page.getByRole("button", { name: "選択した検査を実行 →" });
  await expect(start).toBeDisabled();
  await page.getByLabel(/実施する権限・許可があります/).check();
  const [started] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/scans"),
    ),
    start.click(),
  ]);
  expect(started.status(), await started.text()).toBe(202);
  const job = await started.json();
  expect(job.plan.profile).toBe("network");
  expect(job.plan.ports).toEqual([80]);
  await expect(page.getByTestId("diagnosis-report")).toBeVisible({
    timeout: 150000,
  });
  nextHostRun = Date.now() + 125_000;
  const row = page.locator(`[data-history-id="${job.id}"]`);
  const [response, download] = await Promise.all([
    page.waitForResponse((r) =>
      r.url().endsWith(`/v1/scans/${job.id}/report.pdf`),
    ),
    page.waitForEvent("download"),
    row.getByRole("button", { name: "PDF ↓" }).click(),
  ]);
  expect(response.status()).toBe(200);
  const file = resolve("../../.build/local-advanced-report.pdf");
  await download.saveAs(file);
  expect((await readFile(file)).subarray(0, 5).toString()).toBe("%PDF-");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByLabel("診断の種類").selectOption("host");
  await page.getByRole("button", { name: "AWS接続を準備・設定を表示" }).click();
  await expect(page.getByLabel("読み取り専用ロールのARN")).toBeVisible({
    timeout: 60000,
  });
  const [template] = await Promise.all([
    page.waitForEvent("download"),
    page
      .getByRole("button", { name: "接続用テンプレートをダウンロード ↓" })
      .click(),
  ]);
  const templateFile = resolve("../../.build/local-audit-role.json");
  await template.saveAs(templateFile);
  const document = JSON.parse(await readFile(templateFile, "utf-8"));
  const trust =
    document.Resources.AuditRole.Properties.AssumeRolePolicyDocument
      .Statement[0];
  expect(trust.Condition.StringEquals["sts:ExternalId"]).toMatch(
    /^security-testing-/,
  );
  await page
    .getByLabel("読み取り専用ロールのARN")
    .fill("arn:aws:iam::000000000000:role/security-testing-audit-local-e2e");
  await page
    .getByRole("button", { name: "接続設定を保存", exact: true })
    .click();
  await expect(
    page.getByText(
      "接続設定を保存しました。次に対象リソースを指定してください。",
    ),
  ).toBeVisible();
  await page.getByLabel(/EC2インスタンスID/).fill("i-0123456789abcdef0");
  await page.getByLabel(/実施する権限・許可があります/).check();
  await expect(start).toBeEnabled();
  // Do not submit dummy AWS role: real AWS collection requires a configured target account.
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.locator(".aws-setup").scrollIntoViewIfNeeded();
  await page.screenshot({
    path: resolve("../../.build/advanced-mobile-aws.png"),
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.locator(".advanced-diagnostics").scrollIntoViewIfNeeded();
  await page.screenshot({ path: resolve("../../.build/advanced-desktop.png") });
  page.on("dialog", (d) => d.accept());
  const [removed] = await Promise.all([
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
  expect(removed.status()).toBe(204);
  await expect(selected).toHaveCount(0);
});

test("限定Web検証をボタンで開始しCORS・OPTIONS・TRACEの実応答を記録する", async ({
  page,
}) => {
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
  await page
    .getByLabel("診断する公開サイトのURL")
    .fill("http://fixture.security-testing.test/");
  const [created] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/targets"),
      { timeout: 60000 },
    ),
    page.getByRole("button", { name: "登録 ＋" }).click(),
  ]);
  expect(created.status()).toBe(201);
  const target = await created.json();
  const selected = page.locator(`[data-target-id="${target.sk}"]`);
  await expect(selected).toHaveAttribute("aria-pressed", "true");
  await page
    .getByText("検査内容を選んで手動実行（ネットワーク・AWS・限定Web検証）")
    .click();
  test.setTimeout(360000);
  await page.getByLabel("診断の種類").selectOption("pentest");
  while (Date.now() < nextHostRun) {
    await page.waitForTimeout(Math.min(60_000, nextHostRun - Date.now()));
  }
  await page.getByLabel(/実施する権限・許可があります/).check();
  const [started] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/scans"),
    ),
    page.getByRole("button", { name: "選択した検査を実行 →" }).click(),
  ]);
  expect(started.status(), await started.text()).toBe(202);
  const job = await started.json();
  const result = await page.waitForResponse(
    (r) => r.url().endsWith(`/v1/scans/${job.id}/results`),
    { timeout: 150000 },
  );
  expect(result.status(), await result.text()).toBe(200);
  const report = await result.json();
  expect(report.coverage.profile).toBe("pentest");
  expect(report.findings.find((f: any) => f.rule_id === "CORS").status).toBe(
    "問題を検出せず",
  );
  expect(report.findings.find((f: any) => f.rule_id === "METHODS").status).toBe(
    "確認不能",
  );
  expect(report.findings.find((f: any) => f.rule_id === "TRACE").status).toBe(
    "問題を検出せず",
  );
  expect(report.findings.some((f: any) => f.rule_id === "CSP")).toBe(true);
  await expect(page.getByTestId("diagnosis-report")).toBeVisible();
  await page.getByText("IPAの対策項目と確認できた範囲").click();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  page.on("dialog", (d) => d.accept());
  const [removed] = await Promise.all([
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
  expect(removed.status()).toBe(204);
  await expect(selected).toHaveCount(0);
});
