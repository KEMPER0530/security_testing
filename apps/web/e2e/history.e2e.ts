import { test, expect } from "@playwright/test";
import { resolve } from "node:path";

test.skip(
  process.env.E2E_HISTORY !== "1",
  "LocalStack認証と模擬APIで複数履歴の表示を検証する",
);
test("全対象の過去履歴、対象絞り込み、種類分離とスマートフォン表示", async ({
  page,
}) => {
  const targets = ["one", "two"].map((id) => ({
    sk: `TARGET#${id}`,
    host: `${id}.example`,
    url: `https://${id}.example/`,
    created_at: "2026-11-02T00:00:00Z",
  }));
  const jobs = [
    { id: "latest-one", target_id: "one", plan: { profile: "web" } },
    { id: "older-one", target_id: "one", plan: { profile: "web" } },
    { id: "older-two", target_id: "two", plan: { profile: "web" } },
    { id: "pentest-two", target_id: "two", plan: { profile: "pentest" } },
  ].map((j, i) => ({
    ...j,
    url: `https://${j.target_id}.example/`,
    state: "FAILED",
    error: `表示検証用 ${j.id}`,
    created_at: `2026-11-0${2 - (i % 2)}T00:00:00Z`,
  }));
  await page.route("**/v1/**", async (route) => {
    const url = new URL(route.request().url());
    let data: unknown = {};
    if (url.pathname.endsWith("/targets"))
      data = { items: targets, next_offset: null };
    else if (url.pathname.endsWith("/scans"))
      data =
        url.searchParams.get("offset") === "0"
          ? { items: jobs.slice(0, 1), next_offset: 100 }
          : { items: jobs.slice(1), next_offset: null };
    else if (url.pathname.endsWith("/diagnostic-profiles"))
      data = {
        profiles: {
          web: { checks: { headers: "公開設定" } },
          pentest: { checks: { headers: "公開設定" } },
        },
      };
    else data = jobs.find((j) => url.pathname.endsWith(`/${j.id}`)) || {};
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(data),
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "ログインして始める →" }).click();
  await page.getByLabel("Username or email").fill("developer");
  await page
    .getByLabel("Password", { exact: true })
    .fill("local-development-only");
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  await expect(page.locator("[data-history-id]")).toHaveCount(3);
  await page.getByRole("button", { name: /↗ one.example/ }).click();
  await page.getByRole("button", { name: "Web診断の診断履歴を見る ↓" }).click();
  await expect(page.getByLabel("履歴の表示範囲")).toHaveValue("all");
  await page.getByLabel("履歴の表示範囲").selectOption("selected");
  await expect(page.locator("[data-history-id]")).toHaveCount(2);
  await expect(page.locator('[data-history-id="older-one"]')).toBeVisible();
  await page.getByLabel("履歴の表示範囲").selectOption("all");
  await page.locator('[data-history-id="older-two"] .history-item').click();
  await expect(
    page.getByText("表示検証用 older-two", { exact: true }),
  ).toBeVisible();
  await expect(page.locator('[data-target-id="TARGET#two"]')).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.locator("[data-history-id]")).toHaveCount(3);
  await page.getByRole("button", { name: "Web診断の診断履歴を見る ↓" }).click();
  await page.locator("#history").scrollIntoViewIfNeeded();
  await page.screenshot({
    path: resolve("../../.build/history-scope-desktop.png"),
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator("#history").scrollIntoViewIfNeeded();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: resolve("../../.build/history-scope-mobile.png"),
  });
  await page
    .getByRole("button", { name: "ペネトレーション（限定検証）", exact: true })
    .click();
  await expect(page.locator("[data-history-id]")).toHaveCount(1);
  await expect(page.locator('[data-history-id="pentest-two"]')).toBeVisible();
});
