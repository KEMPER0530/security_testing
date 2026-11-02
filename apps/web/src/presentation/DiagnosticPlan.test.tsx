// @vitest-environment jsdom
import React, { useState } from "react";
import type { ProfileId } from "../domain/diagnostics";
import { DiagnosticTypes } from "./DiagnosticTypes";
import { afterEach, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createApi } from "@security-testing/api-client";
import { DiagnosticPlan } from "./DiagnosticPlan";

const catalog = {
  profiles: {
    web: {
      title: "Web診断",
      scope: "公開ページのみ",
      checks: { headers: "公開設定" },
    },
    network: {
      title: "ネットワーク（限定）",
      scope: "TCP接続確認のみ",
      checks: { dns: "公開IPの名前解決", ports: "TCP接続", tls: "TLS証明書" },
    },
    pentest: {
      title: "ペネトレーション（限定検証）",
      scope: "単一URLの限定検証",
      checks: {
        headers: "公開設定",
        cors: "CORS",
        methods: "許可メソッド",
        trace: "TRACE応答",
      },
    },
    host: {
      title: "AWSホスト",
      scope: "収集済み情報のみ",
      checks: { inventory: "SSM収集状態", inspector: "Inspector結果" },
    },
    cloud: {
      title: "AWSクラウド",
      scope: "読み取り専用設定検査",
      checks: { root_mfa: "ルートMFA", s3: "S3設定" },
    },
  },
  ports: [22, 80, 443],
};
const clients: QueryClient[] = [];
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  clients.forEach((c) => c.clear());
  clients.length = 0;
});
function setup() {
  const requests: Request[] = [];
  const connection = {
    role_arn: null as string | null,
    external_id: "security-testing-test",
    template: { Resources: {} },
    status: "未検証",
  };
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const req = input as Request;
    requests.push(req);
    const path = new URL(req.url).pathname;
    let data: unknown = catalog;
    if (path.endsWith("/aws-connection")) {
      if (req.method === "PUT")
        connection.role_arn = (await req.clone().json()).role_arn;
      data = { ...connection };
    }
    if (path.endsWith("/scans")) data = { id: "queued", state: "QUEUED" };
    return new Response(JSON.stringify(data), {
      headers: { "content-type": "application/json" },
    });
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  clients.push(client);
  const onStarted = vi.fn();
  function Plan() {
    const [profile, setProfile] = useState<ProfileId>("network");
    return (
      <>
        <DiagnosticTypes selected={profile} onSelect={setProfile} />
        <DiagnosticPlan
          key={profile}
          profile={profile}
          principal="plan-test"
          client={createApi("http://localhost:8000", "test-only-token")}
          targetId="example-target"
          targetUrl="https://example.com/"
          disabled={false}
          onStarted={onStarted}
        />
      </>
    );
  }
  render(
    <QueryClientProvider client={client}>
      <Plan />
    </QueryClientProvider>,
  );
  return { requests, onStarted };
}
it("開始操作まで検査せず、選択した範囲と実施許可をAPIへ送る", async () => {
  const { requests, onStarted } = setup();
  await screen.findByLabelText("TCP接続");
  const start = screen.getByRole("button", { name: /を開始 →/ });
  expect(start.hasAttribute("disabled")).toBe(true);
  expect(requests.every((r) => r.method === "GET")).toBe(true);
  fireEvent.click(
    screen.getByRole("button", {
      name: "ペネトレーション（限定検証）",
    }),
  );
  expect(screen.getByText(/本格的な侵入/)).toBeTruthy();
  fireEvent.click(screen.getByLabelText("TRACE応答"));
  fireEvent.click(screen.getByLabelText(/実施する権限・許可があります/));
  fireEvent.click(screen.getByRole("button", { name: /を開始 →/ }));
  await waitFor(() => expect(onStarted).toHaveBeenCalledOnce());
  const request = requests.find(
    (r) => r.method === "POST" && r.url.endsWith("/scans"),
  )!;
  const body = await request.clone().json();
  expect(body).toMatchObject({
    target_id: "example-target",
    profile: "pentest",
    checks: ["headers", "cors", "methods"],
    authorized: true,
    ports: [],
    resources: {},
  });
  expect(request.headers.get("Authorization")).toBe("Bearer test-only-token");
  expect(request.headers.get("Idempotency-Key")).toBeTruthy();
});
it("AWS接続を準備してロールを保存し、指定EC2だけの検査を開始する", async () => {
  const { requests, onStarted } = setup();
  await screen.findByLabelText("TCP接続");
  fireEvent.click(screen.getByRole("button", { name: "AWSホスト診断" }));
  fireEvent.click(
    screen.getByRole("button", { name: "AWS接続を準備・設定を表示" }),
  );
  const role = await screen.findByLabelText("読み取り専用ロールのARN");
  fireEvent.change(role, {
    target: {
      value: "arn:aws:iam::123456789012:role/security-testing-audit-test",
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "接続設定を保存" }));
  await screen.findByText(
    "接続設定を保存しました。次に対象リソースを指定してください。",
  );
  fireEvent.change(screen.getByLabelText(/EC2インスタンスID/), {
    target: { value: "i-0123456789abcdef0" },
  });
  fireEvent.click(screen.getByLabelText(/実施する権限・許可があります/));
  fireEvent.click(screen.getByRole("button", { name: /を開始 →/ }));
  await waitFor(() => expect(onStarted).toHaveBeenCalledOnce());
  const body = await requests
    .find((r) => r.url.endsWith("/scans"))!
    .clone()
    .json();
  expect(body.resources).toEqual({ instances: ["i-0123456789abcdef0"] });
  expect(body).not.toHaveProperty("role_arn");
  expect(body).not.toHaveProperty("external_id");
});
