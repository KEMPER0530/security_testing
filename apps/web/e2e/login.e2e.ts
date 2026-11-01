import { test, expect } from "@playwright/test";

const base = process.env.LOGIN_BASE_URL;
test.skip(
  !base,
  "LOGIN_BASE_URLを指定したときだけCognitoログイン画面を検証する",
);

test("トップは紹介画面を表示し、ログインボタンからフォームへ進む", async ({
  page,
}) => {
  await page.goto(base!);
  await expect(page.getByLabel("メールアドレス / ユーザー名")).toHaveCount(0);
  for (const width of [375, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: width > 900 ? 1000 : 844 });
    await expect(
      page.getByRole("button", { name: "ログイン", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    if (width === 390 || width === 1440)
      await page.screenshot({
        path: `../../.build/landing-${width === 390 ? "mobile" : "desktop"}.png`,
        fullPage: true,
      });
  }
  await page.getByRole("button", { name: "ログイン", exact: true }).click();
  await expect(page).toHaveURL(new URL("/login", base!).href);
  await expect(page.getByLabel("メールアドレス / ユーザー名")).toBeVisible();
  await page.getByRole("link", { name: "トップへ戻る" }).click();
  await expect(page).toHaveURL(new URL(base!).href);
  await page.goto(new URL("/dashboard", base!).href);
  await expect(page).toHaveURL(new URL("/login", base!).href);
});

test("自作ログインはPC・スマートフォンで操作できる", async ({ page }) => {
  await page.goto(base!);
  await page.getByRole("button", { name: "ログイン", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "ログイン", exact: true }),
  ).toBeVisible();
  for (const width of [375, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: width > 900 ? 1000 : 844 });
    await expect(page.getByLabel("メールアドレス / ユーザー名")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "ログイン", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    if (width === 390 || width === 1440) {
      await page.screenshot({
        path: `../../.build/custom-login-${width === 390 ? "mobile" : "desktop"}.png`,
        fullPage: true,
      });
    }
  }
  const password = page.getByLabel("パスワード", { exact: true });
  await expect(password).toHaveAttribute("type", "password");
  await page.getByRole("button", { name: "パスワードを表示" }).click();
  await expect(password).toHaveAttribute("type", "text");
  await page.getByRole("button", { name: "パスワードを非表示" }).click();
  await expect(password).toHaveAttribute("type", "password");
});

test("CognitoへSRP接続し、存在しないテスト用ユーザーはサイト内で拒否する", async ({
  page,
}) => {
  const password = "BrowserTestPassword1!";
  const requests: { flow?: string; body: string }[] = [];
  page.on("request", (request) => {
    if (request.url().startsWith("https://cognito-idp.")) {
      const body = request.postData() || "";
      requests.push({
        flow: body ? JSON.parse(body).AuthFlow : undefined,
        body,
      });
    }
  });
  await page.goto(base!);
  await page.getByRole("button", { name: "ログイン", exact: true }).click();
  await page
    .getByLabel("メールアドレス / ユーザー名")
    .fill(`security-testing-ui-probe-${Date.now()}@example.invalid`);
  await page.getByLabel("パスワード", { exact: true }).fill(password);
  await page.getByRole("button", { name: "ログイン", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("正しくありません", {
    timeout: 30000,
  });
  expect(page.url()).toBe(new URL("/login", base!).href);
  expect(requests.some((request) => request.flow === "USER_SRP_AUTH")).toBe(
    true,
  );
  expect(requests.every((request) => !request.body.includes(password))).toBe(
    true,
  );
  await expect(page.getByLabel("パスワード", { exact: true })).toHaveValue("");
  await expect(page.getByRole("button", { name: "診断を開始 →" })).toHaveCount(
    0,
  );
});
