import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

test.skip(
  process.env.E2E_FETCH_FAILURE !== "1",
  "制御下のfixtureの失敗表示を明示実行するときだけ検証する",
);
test("取得失敗の理由をAPIと画面に表示する", async ({ page }) => {
  test.setTimeout(300000);
  const env = await readFile(resolve("../../.env"), "utf8");
  const api = env
    .split("\n")
    .find((line) => line.startsWith("VITE_API_URL="))!
    .slice(13);
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
  async function apiGet(path: string) {
    return page.evaluate(
      async ({ api, path }) => {
        const key = Object.keys(sessionStorage).find((key) =>
          key.startsWith("oidc.user:"),
        )!;
        const token = JSON.parse(sessionStorage.getItem(key)!).access_token;
        const response = await fetch(api + path, {
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(60000),
        });
        return { status: response.status, body: await response.json() };
      },
      { api, path },
    );
  }
  const history = await apiGet("/v1/scans");
  expect(history.status).toBe(200);
  const jobs = history.body.items;
  if (jobs.length)
    await expect
      .poll(() => Date.now(), { timeout: 160000, intervals: [1000] })
      .toBeGreaterThan(Date.parse(jobs[0].created_at) + 150000);
  await page
    .getByLabel("診断する公開サイトのURL")
    .fill(
      `http://fixture.security-testing.test/absent-diagnostic-page-${Date.now()}`,
    );
  await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        response.url().endsWith("/v1/targets"),
    ),
    page.getByRole("button", { name: "登録 ＋" }).click(),
  ]);
  const [response] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        response.url().endsWith("/v1/scans"),
    ),
    page.getByRole("button", { name: "Web診断を開始 →" }).click(),
  ]);
  expect(response.status()).toBe(202);
  const job = await response.json();
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("HTTP 404", { timeout: 120000 });
  await expect(alert).toContainText(
    "対象サイトから正常なページが返りませんでした",
  );
  await expect(alert).toContainText("安全性は判定していません");
  const saved = await apiGet(`/v1/scans/${job.id}`);
  expect(saved.status).toBe(200);
  expect(saved.body.error_code).toBe("HTTP_STATUS");
  await page.setViewportSize({ width: 390, height: 844 });
  await alert.scrollIntoViewIfNeeded();
  await page.screenshot({
    path: resolve("../../.build/scan-failure-mobile.png"),
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  console.log(
    "Controlled fixture: HTTP 404 reason persisted and displayed; no external target fetched",
  );
});
