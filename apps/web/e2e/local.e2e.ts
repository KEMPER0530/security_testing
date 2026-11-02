import { test, expect } from "@playwright/test";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
// Real Keycloak + LocalStack only. No route interception or manufactured findings.
test("ログインから事前設定なしの診断・結果まで", async ({ page }) => {
  test.setTimeout(480000);
  const env = await readFile(resolve("../../.env"), "utf8");
  const api = env
    .split("\n")
    .find((line) => line.startsWith("VITE_API_URL="))!
    .split("=")
    .slice(1)
    .join("=");
  async function apiGet(path: string) {
    return page.evaluate(
      async ({ url }) => {
        const key = Object.keys(sessionStorage).find((k) =>
          k.startsWith("oidc.user:"),
        )!;
        const token = JSON.parse(sessionStorage.getItem(key)!).access_token;
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) throw new Error(`API status ${response.status}`);
        return response.json();
      },
      { url: api + path },
    );
  }
  async function waitForCooldown(created: string) {
    await expect
      .poll(() => Date.now(), { timeout: 160000, intervals: [1000] })
      .toBeGreaterThan(Date.parse(created) + 150000);
  }
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
  const [registration] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/targets"),
      { timeout: 60000 },
    ),
    page.getByRole("button", { name: "登録 ＋" }).click(),
  ]);
  expect(registration.status(), await registration.text()).toBe(201);
  const registered = await registration.json();
  await expect(
    page.locator(`[data-target-id="${registered.sk}"]`),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByRole("heading", { name: "所有確認", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "システム重要度を設定" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Web診断を開始 →" }),
  ).toBeEnabled();
  const history = await apiGet("/v1/scans");
  if (history.items.length) await waitForCooldown(history.items[0].created_at);
  const [firstScan] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === "POST" && r.url().endsWith("/v1/scans"),
    ),
    page.getByRole("button", { name: "Web診断を開始 →" }).click(),
  ]);
  expect(firstScan.status(), await firstScan.text()).toBe(202);
  const firstJob = await firstScan.json();
  await expect(page.getByTestId("scan-progress")).toBeVisible({
    timeout: 30000,
  });
  if (
    (await page.getByTestId("scan-progress").getAttribute("aria-busy")) ===
    "true"
  ) {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator("#results").scrollIntoViewIfNeeded();
    await page.screenshot({ path: resolve("../../.build/mobile-loading.png") });
  }
  await page.reload();
  await expect(page.locator("#results")).toHaveAttribute(
    "data-job-id",
    firstJob.id,
    { timeout: 30000 },
  );
  await page.setViewportSize({ width: 1440, height: 1000 });

  await expect(page.locator("#results")).toHaveAttribute(
    "data-job-id",
    firstJob.id,
  );
  await expect(page.getByTestId("diagnosis-report")).toBeVisible({
    timeout: 120000,
  });
  await expect(
    page.getByRole("columnheader", { name: "CVSS", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("columnheader", { name: "深刻度（暫定）" }),
  ).toBeVisible();
  await expect(page.locator("table")).toContainText("未評価");
  console.log(
    "E2E: authentication, direct public-page scan, severity results passed",
  );
  const first = await apiGet(`/v1/scans/${firstJob.id}/results`);
  for (const width of [375, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 844 });
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth))
      .toBeLessThanOrEqual(width);
    if (width <= 800)
      await expect(page.locator(".finding-cards")).toBeVisible();
    else await expect(page.locator(".findings-table")).toBeVisible();
    expect(
      await page.getByText("REACT + PYTHON", { exact: false }).count(),
    ).toBe(0);
    expect(
      await page.getByText("Authorized checks only", { exact: true }).count(),
    ).toBe(0);
    if (width === 390) {
      await page.locator("#results").scrollIntoViewIfNeeded();
      await page.screenshot({
        path: resolve("../../.build/mobile-diagnosis.png"),
      });
    }
  }
  console.log(
    "E2E: restored job, automatic results, and responsive widths 375/390/768/1440 passed",
  );
  if (process.env.E2E_QUICK === "1") return;

  const configPath = resolve("../../local/fixtures/nginx.conf");
  const originalConfig = await readFile(configPath, "utf8");
  const reload = () =>
    execFileSync(
      "docker",
      ["compose", "exec", "-T", "fixture", "nginx", "-s", "reload"],
      { cwd: resolve("../.."), stdio: "pipe" },
    );
  try {
    execFileSync(
      resolve("../../.venv/bin/python"),
      [resolve("../../scripts/fixture.py"), "secure"],
      { cwd: resolve("../.."), stdio: "pipe" },
    );
    reload();
    await waitForCooldown(firstJob.created_at);
    const [secondScan] = await Promise.all([
      page.waitForResponse(
        (r) => r.request().method() === "POST" && r.url().endsWith("/v1/scans"),
      ),
      page.getByRole("button", { name: "Web診断を開始 →" }).click(),
    ]);
    expect(secondScan.status(), await secondScan.text()).toBe(202);
    const secondJob = await secondScan.json();
    await expect
      .poll(async () => (await apiGet(`/v1/scans/${secondJob.id}`)).state, {
        timeout: 120000,
      })
      .toBe("SUCCEEDED");
    await expect(page.locator("#results")).toHaveAttribute(
      "data-job-id",
      secondJob.id,
    );
    await expect(page.getByTestId("diagnosis-report")).toBeVisible({
      timeout: 120000,
    });
    const second = await apiGet(`/v1/scans/${secondJob.id}/results`);
    expect(second.summary.configuration_count).toBeLessThan(
      first.summary.configuration_count,
    );
    const comparison = await apiGet(
      `/v1/scans/${secondJob.id}/comparison?previous_id=${firstJob.id}`,
    );
    expect(
      comparison.items.some(
        (item: { rule_id: string; change: string }) =>
          item.rule_id === "CSP" && item.change === "解消",
      ),
    ).toBe(true);
    await page.screenshot({
      path: resolve("../../.build/workspace-preview.png"),
      fullPage: true,
    });
    await writeFile(
      resolve("../../.build/integration-result.json"),
      JSON.stringify(
        { before: first.summary, after: second.summary, comparison },
        null,
        2,
      ),
    );
    console.log("E2E: improved settings, re-scan, and comparison passed");
  } finally {
    await writeFile(configPath, originalConfig);
    reload();
  }
});
