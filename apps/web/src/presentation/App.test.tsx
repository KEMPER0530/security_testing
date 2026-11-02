// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import {
  render,
  screen,
  fireEvent,
  act,
  cleanup,
  waitFor,
} from "@testing-library/react";
vi.mock("../infrastructure/identity", () => ({
  identity: {
    getUser: vi.fn(async () => null),
    signinRedirect: vi.fn(async () => {}),
    signoutRedirect: vi.fn(async () => {}),
    events: {
      addUserLoaded: vi.fn(),
      addUserUnloaded: vi.fn(),
      addAccessTokenExpired: vi.fn(),
      removeUserLoaded: vi.fn(),
      removeUserUnloaded: vi.fn(),
      removeAccessTokenExpired: vi.fn(),
    },
  },
}));
import { MemoryRouter } from "react-router-dom";
import type { AuthSession } from "../application/auth";
import { App } from "./App";
import { identity } from "../infrastructure/identity";
it("ログイン前に診断操作を表示せずOIDCログインへ進む", async () => {
  render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );
  const button = await screen.findByRole("button", {
    name: "ログインして始める →",
  });
  await waitFor(() => expect(button.hasAttribute("disabled")).toBe(false));
  fireEvent.click(button);
  await waitFor(() => expect(identity.signinRedirect).toHaveBeenCalledOnce());
  expect(screen.queryByRole("button", { name: "診断を開始 →" })).toBeNull();
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.mocked(identity.getUser).mockResolvedValue(null);
  delete identity.password;
  localStorage.clear();
});
it("ログイン期限切れで診断画面を閉じ再ログインへ戻す", async () => {
  vi.mocked(identity.getUser).mockResolvedValueOnce({
    access_token: "local-test-token",
    expired: false,
  } as AuthSession);
  vi.spyOn(globalThis, "fetch").mockImplementation(
    async () =>
      new Response(JSON.stringify({ items: [], next_offset: null }), {
        headers: { "content-type": "application/json" },
      }),
  );
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByRole("heading", { name: "診断ワークスペース" });
  const expired = vi
    .mocked(identity.events.addAccessTokenExpired)
    .mock.calls.at(-1)![0];
  act(() => expired());
  expect(
    await screen.findByRole("button", { name: "ログインして始める →" }),
  ).toBeTruthy();
  expect(screen.queryByRole("button", { name: "診断を開始 →" })).toBeNull();
  client.clear();
});

it("登録後の一覧再取得でも新しく登録した対象の選択を維持する", async () => {
  localStorage.clear();
  vi.mocked(identity.getUser).mockResolvedValueOnce({
    access_token: "local-test-token",
    expired: false,
    profile: { sub: "registration-test" },
  } as AuthSession);
  const oldTarget = {
    sk: "TARGET#old",
    host: "old.example",
    url: "https://old.example/",
    created_at: "2026-11-01T00:00:00Z",
    verified_until: 0,
    assessment: null,
  };
  const newTarget = {
    ...oldTarget,
    sk: "TARGET#new",
    host: "new.example",
    url: "https://new.example/",
    created_at: "2026-11-01T01:00:00Z",
  };
  let registered = false;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const request = input as Request;
    if (
      new URL(request.url).pathname.endsWith("/v1/targets") &&
      request.method === "POST"
    ) {
      registered = true;
      // A refetch can already contain the new target before POST resolves.
      client.setQueryData(["registration-test", "targets"], {
        items: [oldTarget, newTarget],
        next_offset: null,
      });
      return new Response(JSON.stringify(newTarget), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    }
    const items = new URL(request.url).pathname.endsWith("/v1/targets")
      ? registered
        ? [oldTarget, newTarget]
        : [oldTarget]
      : [];
    return new Response(JSON.stringify({ items, next_offset: null }), {
      headers: { "content-type": "application/json" },
    });
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByRole("button", { name: /old.example/ });
  fireEvent.change(screen.getByLabelText("診断する公開サイトのURL"), {
    target: { value: "https://new.example/" },
  });
  fireEvent.click(screen.getByRole("button", { name: "登録 ＋" }));
  const selected = await screen.findByRole("button", { name: /new.example/ });
  expect(selected.getAttribute("aria-pressed")).toBe("true");
  expect(
    screen
      .getByRole("button", { name: /old.example/ })
      .getAttribute("aria-pressed"),
  ).toBe("false");
  expect(screen.queryByRole("heading", { name: "所有確認" })).toBeNull();
  expect(
    screen.queryByRole("heading", { name: "システム重要度を設定" }),
  ).toBeNull();
  expect(
    screen
      .getByRole("button", { name: "診断を開始 →" })
      .hasAttribute("disabled"),
  ).toBe(false);
  client.clear();
});

function nativeAuth() {
  identity.password = {
    signIn: vi.fn(),
    confirmSignIn: vi.fn(),
    resetPassword: vi.fn(),
    confirmResetPassword: vi.fn(),
  };
}
function renderRoute(route = "/") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  vi.spyOn(globalThis, "fetch").mockImplementation(
    async () =>
      new Response(JSON.stringify({ items: [], next_offset: null }), {
        headers: { "content-type": "application/json" },
      }),
  );
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}
it("未ログインのトップは紹介を表示し、ボタンから自作ログインへ進む", async () => {
  nativeAuth();
  const client = renderRoute();
  const button = screen.getByRole("button", { name: "ログイン" });
  expect(screen.queryByLabelText("メールアドレス / ユーザー名")).toBeNull();
  await waitFor(() => expect(button.hasAttribute("disabled")).toBe(false));
  fireEvent.click(button);
  await screen.findByLabelText("メールアドレス / ユーザー名");
  expect(identity.signinRedirect).not.toHaveBeenCalled();
  client.clear();
});
it("ログイン済みでもトップを表示し、ボタンから直接ダッシュボードへ進む", async () => {
  nativeAuth();
  vi.mocked(identity.getUser).mockResolvedValue({
    access_token: "test-only",
    expired: false,
    profile: { sub: "routing" },
  });
  const client = renderRoute();
  const button = screen.getByRole("button", { name: "ログイン" });
  await waitFor(() => expect(button.hasAttribute("disabled")).toBe(false));
  expect(
    screen.queryByRole("heading", { name: "診断ワークスペース" }),
  ).toBeNull();
  fireEvent.click(button);
  await screen.findByRole("heading", { name: "診断ワークスペース" });
  expect(screen.queryByLabelText("メールアドレス / ユーザー名")).toBeNull();
  expect(identity.getUser).toHaveBeenCalledTimes(2);
  client.clear();
});
it("トップ表示後にセッションが失効した場合はボタンでログインへ進む", async () => {
  nativeAuth();
  vi.mocked(identity.getUser).mockResolvedValueOnce({
    access_token: "test-only",
    expired: false,
    profile: { sub: "routing-test" },
  });
  const client = renderRoute();
  const button = screen.getByRole("button", { name: "ログイン" });
  await waitFor(() => expect(button.hasAttribute("disabled")).toBe(false));
  fireEvent.click(button);
  await screen.findByLabelText("メールアドレス / ユーザー名");
  client.clear();
});
it("未ログインでダッシュボードへ直接アクセスするとログインへ進む", async () => {
  nativeAuth();
  const client = renderRoute("/dashboard");
  await screen.findByLabelText("メールアドレス / ユーザー名");
  expect(fetch).not.toHaveBeenCalled();
  client.clear();
});
it("ログイン画面で認証が完了するとダッシュボードへ進む", async () => {
  nativeAuth();
  const client = renderRoute("/login");
  await screen.findByLabelText("メールアドレス / ユーザー名");
  const loaded = vi.mocked(identity.events.addUserLoaded).mock.calls.at(-1)![0];
  act(() =>
    loaded({
      access_token: "test-only",
      expired: false,
      profile: { sub: "routing-test" },
    }),
  );
  await screen.findByRole("heading", { name: "診断ワークスペース" });
  client.clear();
});

it("表示中の結果と異なる履歴のPDFを、その履歴IDで認証付き取得する", async () => {
  vi.mocked(identity.getUser).mockResolvedValue({
    access_token: "test-pdf-token",
    expired: false,
    profile: { sub: "pdf-history" },
  } as AuthSession);
  const target = {
    sk: "TARGET#one",
    host: "history.example",
    url: "https://history.example/",
    created_at: "2026-11-02T00:00:00Z",
  };
  const jobs = ["new", "old"].map((id) => ({
    id,
    target_id: "one",
    url: target.url,
    state: "FAILED",
    created_at: "2026-11-02T00:00:00Z",
    error: "テスト用の失敗",
  }));
  const fetched: Request[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const request = input as Request;
    fetched.push(request);
    const path = new URL(request.url).pathname;
    if (path.endsWith("report.pdf"))
      return new Response(
        new Blob(["%PDF-1.4 sample"], { type: "application/pdf" }),
        { headers: { "content-type": "application/pdf" } },
      );
    const data = path.endsWith("/targets")
      ? { items: [target], next_offset: null }
      : path.endsWith("/scans")
        ? { items: jobs, next_offset: null }
        : jobs[0];
    return new Response(JSON.stringify(data), {
      headers: { "content-type": "application/json" },
    });
  });
  Object.defineProperty(URL, "createObjectURL", {
    configurable: true,
    value: vi.fn(() => "blob:test-pdf"),
  });
  Object.defineProperty(URL, "revokeObjectURL", {
    configurable: true,
    value: vi.fn(),
  });
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const { container } = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByRole("button", { name: /↗ history.example/ });
  fireEvent.click(
    container.querySelector('[data-history-id="new"] .history-item')!,
  );
  await screen.findByText("テスト用の失敗");
  fireEvent.click(
    container.querySelector('[data-history-id="old"] .pdf-button')!,
  );
  await waitFor(() => expect(click).toHaveBeenCalledOnce());
  const request = fetched.find((r) => r.url.endsWith("/old/report.pdf"))!;
  expect(request.headers.get("Authorization")).toBe("Bearer test-pdf-token");
  expect(request.headers.get("Accept")).toBe("application/pdf");
  expect(fetched.some((r) => r.url.endsWith("/new/report.pdf"))).toBe(false);
  client.clear();
});

it("履歴・対象の削除は確認を要求し、履歴だけ削除しても対象を残す", async () => {
  vi.mocked(identity.getUser).mockResolvedValue({
    access_token: "test-delete-token",
    expired: false,
    profile: { sub: "delete-history" },
  } as AuthSession);
  let targets = [
    {
      sk: "TARGET#one",
      host: "delete.example",
      url: "https://delete.example/",
      created_at: "2026-11-02T00:00:00Z",
    },
  ];
  let jobs = [
    {
      id: "saved",
      target_id: "one",
      url: targets[0].url,
      state: "SUCCEEDED",
      created_at: "2026-11-02T00:00:00Z",
    },
  ];
  const deleted: string[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const request = input as Request,
      path = new URL(request.url).pathname;
    if (request.method === "DELETE") {
      deleted.push(path);
      if (path.includes("/scans/")) jobs = [];
      else targets = [];
      return new Response(null, { status: 204 });
    }
    return new Response(
      JSON.stringify({
        items: path.endsWith("/targets") ? targets : jobs,
        next_offset: null,
      }),
      { headers: { "content-type": "application/json" } },
    );
  });
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "診断履歴を削除" }),
  );
  expect(confirm).toHaveBeenCalledOnce();
  expect(deleted).toEqual([]);
  confirm.mockReturnValue(true);
  fireEvent.click(screen.getByRole("button", { name: "診断履歴を削除" }));
  await waitFor(() =>
    expect(screen.queryByRole("button", { name: "診断履歴を削除" })).toBeNull(),
  );
  expect(screen.getByRole("button", { name: /↗ delete.example/ })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "診断対象を削除" }));
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: /↗ delete.example/ }),
    ).toBeNull(),
  );
  expect(deleted.map((path) => path.slice(path.lastIndexOf("/v1/")))).toEqual([
    "/v1/scans/saved",
    "/v1/targets/one",
  ]);
  client.clear();
});
