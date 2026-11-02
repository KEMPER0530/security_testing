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
  expect(screen.queryByRole("button", { name: "Web診断を開始 →" })).toBeNull();
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
  expect(screen.queryByRole("button", { name: "Web診断を開始 →" })).toBeNull();
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
      .getByRole("button", { name: "Web診断を開始 →" })
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

it.each(["web-job", "network-job"])(
  "診断種類を切り替えて結果を分離し、旧保存ID（%s）からも復元する",
  async (storedJob) => {
    const principal = "profile-routing";
    localStorage.setItem(`security-testing:${principal}:target`, "TARGET#one");
    localStorage.setItem(`security-testing:${principal}:job`, storedJob);
    vi.mocked(identity.getUser).mockResolvedValue({
      access_token: "test-only",
      expired: false,
      profile: { sub: principal },
    } as AuthSession);
    const target = {
      sk: "TARGET#one",
      url: "https://example.com/",
      host: "example.com",
      created_at: "2026-11-02T00:00:00Z",
    };
    const jobs = ["web", "network"].map((profile) => ({
      id: `${profile}-job`,
      target_id: "one",
      url: target.url,
      state: "SUCCEEDED",
      created_at: "2026-11-02T00:00:00Z",
      plan: { profile },
    }));
    const reports = Object.fromEntries(
      jobs.map((job) => [
        job.id,
        {
          job_id: job.id,
          plan: job.plan,
          coverage: {
            profile: job.plan.profile,
            scope: `${job.plan.profile}の範囲`,
            not_tested: [],
          },
          summary: { configuration_count: 0, cvss_severity_counts: {} },
          findings: [
            {
              rule_id: job.plan.profile === "web" ? "CSP" : "PORT_443",
              title:
                job.plan.profile === "web"
                  ? "Web-only CSP"
                  : "Network-only TCP",
              status: "確認不能",
              cvss: null,
            },
          ],
        },
      ]),
    );
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const request = input as Request;
      const path = new URL(request.url).pathname;
      let data: unknown = {};
      if (path.endsWith("/diagnostic-profiles"))
        data = {
          profiles: {
            web: { checks: { headers: "公開設定" } },
            network: { checks: { dns: "DNS" } },
            host: { checks: { inventory: "Inventory" } },
          },
        };
      else if (path.endsWith("/targets"))
        data = { items: [target], next_offset: null };
      else if (path.endsWith("/scans"))
        data = { items: jobs, next_offset: null };
      else if (path.endsWith("/aws-connection"))
        return new Response(JSON.stringify({ error: { message: "未設定" } }), {
          status: 404,
          headers: { "content-type": "application/json" },
        });
      else {
        const entry = jobs.find((j) => path.includes(j.id));
        if (entry) data = path.endsWith("/results") ? reports[entry.id] : entry;
      }
      return new Response(JSON.stringify(data), {
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
    await screen.findAllByText("Web-only CSP");
    expect(
      screen
        .getByRole("button", { name: "Web診断" })
        .getAttribute("aria-pressed"),
    ).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "ネットワーク診断" }));
    expect(screen.queryAllByText("Web-only CSP")).toHaveLength(0);
    await screen.findAllByText("Network-only TCP");
    expect(
      screen
        .getByTestId("diagnosis-report")
        .getAttribute("data-result-profile"),
    ).toBe("network");
    expect(document.querySelector('[data-history-id="web-job"]')).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "AWSホスト診断" }));
    expect(screen.queryByTestId("diagnosis-report")).toBeNull();
    await screen.findByText(/AWSホスト診断の結果が選択中の対象にはありません/);
    expect(
      document.querySelector('[data-history-id="network-job"]'),
    ).toBeNull();
    client.clear();
  },
);

it("全ページのWeb履歴を全対象から表示し、対象を絞っても古い履歴を残す", async () => {
  const principal = "history-scope";
  localStorage.setItem(`security-testing:${principal}:target`, "TARGET#one");
  localStorage.setItem(`security-testing:${principal}:job`, "new-one");
  vi.mocked(identity.getUser).mockResolvedValue({
    access_token: "test-only",
    expired: false,
    profile: { sub: principal },
  } as AuthSession);
  const targets = ["one", "two"].map((id) => ({
    sk: `TARGET#${id}`,
    url: `https://${id}.example/`,
    host: `${id}.example`,
    created_at: "2026-11-02T00:00:00Z",
  }));
  const jobs = [
    { id: "new-one", target_id: "one", plan: { profile: "web" } },
    { id: "old-one", target_id: "one" },
    { id: "other-two", target_id: "two", plan: { profile: "web" } },
    { id: "pentest-two", target_id: "two", plan: { profile: "pentest" } },
  ].map((j) => ({
    ...j,
    url: `https://${j.target_id}.example/`,
    state: "FAILED",
    created_at: "2026-11-02T00:00:00Z",
    error: `保存済み結果 ${j.id}`,
  }));
  const offsets: string[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const req = input as Request;
    const url = new URL(req.url);
    let data: unknown = {};
    if (url.pathname.endsWith("/targets"))
      data = { items: targets, next_offset: null };
    else if (url.pathname.endsWith("/scans")) {
      offsets.push(url.searchParams.get("offset")!);
      data =
        url.searchParams.get("offset") === "0"
          ? { items: jobs.slice(0, 1), next_offset: 100 }
          : { items: jobs.slice(1), next_offset: null };
    } else if (url.pathname.endsWith("/diagnostic-profiles"))
      data = { profiles: { web: { checks: { headers: "公開設定" } } } };
    else data = jobs.find((j) => url.pathname.endsWith(`/${j.id}`)) || {};
    return new Response(JSON.stringify(data), {
      headers: { "content-type": "application/json" },
    });
  });
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
  await screen.findByText("保存済み結果 new-one");
  await waitFor(() =>
    expect(container.querySelectorAll("[data-history-id]")).toHaveLength(3),
  );
  expect(offsets).toContain("100");
  expect(container.querySelector('[data-history-id="pentest-two"]')).toBeNull();
  expect(container.querySelector('[data-history-id="old-one"]')).not.toBeNull();
  fireEvent.change(screen.getByLabelText("履歴の表示範囲"), {
    target: { value: "selected" },
  });
  expect(container.querySelectorAll("[data-history-id]")).toHaveLength(2);
  expect(container.querySelector('[data-history-id="old-one"]')).not.toBeNull();
  expect(container.querySelector('[data-history-id="other-two"]')).toBeNull();
  fireEvent.change(screen.getByLabelText("履歴の表示範囲"), {
    target: { value: "all" },
  });
  fireEvent.click(
    container.querySelector('[data-history-id="other-two"] .history-item')!,
  );
  await screen.findByText("保存済み結果 other-two");
  expect(
    container
      .querySelector('[data-target-id="TARGET#two"]')
      ?.getAttribute("aria-pressed"),
  ).toBe("true");
  expect(container.querySelectorAll("[data-history-id]")).toHaveLength(3);
  expect(screen.getAllByRole("button", { name: "PDF ↓" })).toHaveLength(3);
  client.clear();
});
