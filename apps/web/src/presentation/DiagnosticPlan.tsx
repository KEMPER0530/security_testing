import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { createApi } from "@security-testing/api-client";
import { InfoTooltip } from "./InfoTooltip";
import { diagnosticProfiles, type ProfileId } from "../domain/diagnostics";

type Item = Record<string, any>;
type Client = ReturnType<typeof createApi>;
function result(value: { data?: unknown; error?: any }): Item {
  if (value.error)
    throw new Error(
      value.error?.error?.message ||
        "設定を確認できません。もう一度お試しください。",
    );
  return value.data as Item;
}
const fields: Record<string, [string, string]> = {
  instances: ["EC2インスタンスID", "i-0123456789abcdef0"],
  buckets: ["S3バケット名", "example-audit-bucket"],
  security_groups: ["セキュリティグループID", "sg-0123456789abcdef0"],
  trails: [
    "CloudTrailのARN",
    "arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/example",
  ],
};
export function DiagnosticPlan({
  client,
  targetId,
  targetUrl,
  disabled,
  onStarted,
  profile,
  principal,
}: {
  client: Client;
  targetId: string;
  targetUrl: string;
  disabled: boolean;
  onStarted: (job: Item) => void;
  profile: ProfileId;
  principal: string;
}) {
  const [checks, setChecks] = useState<string[] | null>(null);
  const [ports, setPorts] = useState<number[]>([443]);
  const [resources, setResources] = useState<Record<string, string>>({});
  const [region, setRegion] = useState("ap-northeast-1");
  const [authorized, setAuthorized] = useState(false);
  const [connectionOverride, setConnection] = useState<Item | null>(null);
  const [arn, setArn] = useState<string | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const catalog = useQuery({
    queryKey: ["diagnostic-profiles"],
    queryFn: async () => result(await client.GET("/v1/diagnostic-profiles")),
    staleTime: 300_000,
  });
  const profiles = catalog.data?.profiles || {};
  const current = profiles[profile];
  const selectedChecks =
    checks ??
    Object.keys(
      current?.checks ||
        (profile === "web" ? { headers: "公開ページの応答・保護設定" } : {}),
    );
  const info = diagnosticProfiles[profile];
  const aws = profile === "host" || profile === "cloud";
  const savedConnection = useQuery({
    queryKey: [principal, "aws-connection", targetId],
    queryFn: async () => {
      const response = await client.GET(
        "/v1/targets/{target_id}/aws-connection",
        { params: { path: { target_id: targetId } } },
      );
      if (response.response.status === 404) return null;
      return result(response);
    },
    enabled: aws && Boolean(targetId),
    staleTime: 0,
  });
  const connection = connectionOverride ?? savedConnection.data ?? null;
  const roleArn = arn ?? connection?.role_arn ?? "";
  const kinds =
    profile === "host"
      ? ["instances"]
      : profile === "cloud"
        ? ([
            selectedChecks.includes("s3") && "buckets",
            selectedChecks.includes("security_groups") && "security_groups",
            selectedChecks.includes("cloudtrail") && "trails",
          ].filter(Boolean) as string[])
        : [];
  const blocked = disabled || Boolean(busy);
  async function action(label: string, fn: () => Promise<void>) {
    if (blocked) return;
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "処理を完了できませんでした。");
    } finally {
      setBusy("");
    }
  }
  function toggle(value: string) {
    setChecks(
      selectedChecks.includes(value)
        ? selectedChecks.filter((v) => v !== value)
        : [...selectedChecks, value],
    );
    setAuthorized(false);
  }
  return (
    <div className="diagnostic-configuration" data-profile={profile}>
      <h3>{info.title}の検査内容</h3>
      <p className="muted">{info.scope}</p>
      {catalog.isPending && <p role="status">検査一覧を読み込んでいます…</p>}
      {catalog.error && (
        <p role="alert">
          {catalog.error.message}
          <button className="quiet" onClick={() => void catalog.refetch()}>
            再取得
          </button>
        </p>
      )}
      {(current || profile === "web") && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void action("選択した検査を受け付けています", async () => {
              const job = result(
                await client.POST("/v1/scans", {
                  body: {
                    target_id: targetId,
                    profile,
                    checks: selectedChecks,
                    ports:
                      profile === "network" && selectedChecks.includes("ports")
                        ? ports
                        : [],
                    resources: Object.fromEntries(
                      kinds.map((kind) => [
                        kind,
                        (resources[kind] || "").split(/[,\s]+/).filter(Boolean),
                      ]),
                    ),
                    region,
                    authorized: profile === "web" ? false : authorized,
                  },
                  params: {
                    header: { "idempotency-key": crypto.randomUUID() },
                  },
                }),
              );
              onStarted(job);
              setAuthorized(false);
            });
          }}
        >
          <p className="scope-note">{current?.scope || info.scope}</p>
          {profile === "pentest" && (
            <p className="notice">
              この機能は公開ページへの限定検証です。本格的な侵入、権限の奪取、別システムへの横展開は実施しません。ログインや入力処理を含む包括的なペネトレーションテストは専門家の検証が必要です。
            </p>
          )}
          {profile === "host" && (
            <p className="hint">
              SSMとInspectorがすでに集めた情報を読みます。対象EC2のInventory収集・Inspector検査を先に有効にしてください。未収集や7日を超える情報は「確認不能」と表示します。
            </p>
          )}
          <fieldset disabled={blocked}>
            <legend>実施する検査</legend>
            <div className="check-options">
              {Object.entries(
                current?.checks || { headers: "公開ページの応答・保護設定" },
              ).map(([key, title]) => (
                <label className="check-option" key={key}>
                  <input
                    type="checkbox"
                    checked={selectedChecks.includes(key)}
                    onChange={() => toggle(key)}
                  />
                  {String(title)}
                </label>
              ))}
            </div>
          </fieldset>
          {profile === "network" && selectedChecks.includes("ports") && (
            <fieldset disabled={blocked}>
              <legend>
                TCPポート（最大8個）
                <InfoTooltip
                  label="TCPポートの説明"
                  text="サイトやサーバーへの通信の入口です。接続できるかだけを確認し、製品の弱点や侵入の可否は検査しません。22はSSH、443はHTTPS、3389はWindowsの遠隔管理などに使います。"
                />
              </legend>
              <div className="check-options">
                {(catalog.data?.ports || []).map((port: number) => (
                  <label className="check-option" key={port}>
                    <input
                      type="checkbox"
                      checked={ports.includes(port)}
                      disabled={!ports.includes(port) && ports.length >= 8}
                      onChange={() => {
                        setPorts(
                          ports.includes(port)
                            ? ports.filter((v) => v !== port)
                            : [...ports, port],
                        );
                        setAuthorized(false);
                      }}
                    />
                    {port}
                  </label>
                ))}
              </div>
            </fieldset>
          )}
          {savedConnection.error && (
            <p role="alert">
              AWS接続設定の取得に失敗しました。{savedConnection.error.message}
            </p>
          )}
          {aws && (
            <div className="aws-setup">
              <h3>AWSへの読み取り専用接続</h3>
              <p className="hint">
                初回は、検査対象のAWSアカウントの管理者に接続用ロールを作成してもらいます。アクセスキーやパスワードの入力は不要です。外部のサイトのAWS内部情報は、その管理者の設定なしには読めません。
              </p>
              <button
                type="button"
                className="quiet"
                disabled={blocked}
                onClick={() =>
                  void action("AWS接続情報を準備しています", async () => {
                    const data = result(
                      await client.POST(
                        "/v1/targets/{target_id}/aws-connection",
                        { params: { path: { target_id: targetId } } },
                      ),
                    );
                    setConnection(data);
                    setArn(data.role_arn || "");
                  })
                }
              >
                AWS接続を準備・設定を表示
              </button>
              {connection && (
                <>
                  <ol>
                    <li>下のテンプレートをダウンロードします。</li>
                    <li>
                      対象AWSのCloudFormationでテンプレートを指定し、IAMロール作成を承認してスタックを作成します。
                    </li>
                    <li>
                      作成後の「出力」にあるRoleArnを下に貼り、保存します。
                    </li>
                  </ol>
                  <p className="hint">
                    テンプレートは診断専用の読み取り権限と、この接続専用のExternalIdを設定します。保存後、診断開始時に接続とExternalIdの必須条件を検証します。
                  </p>
                  <button
                    type="button"
                    className="quiet"
                    onClick={() => {
                      const url = URL.createObjectURL(
                        new Blob(
                          [JSON.stringify(connection.template, null, 2)],
                          { type: "application/json" },
                        ),
                      );
                      const link = document.createElement("a");
                      link.href = url;
                      link.download = "security-testing-audit-role.json";
                      link.click();
                      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
                    }}
                  >
                    接続用テンプレートをダウンロード ↓
                  </button>
                  <label htmlFor="audit-role-arn">
                    読み取り専用ロールのARN
                  </label>
                  <input
                    id="audit-role-arn"
                    value={roleArn}
                    onChange={(e) => setArn(e.target.value)}
                    disabled={blocked}
                    placeholder="arn:aws:iam::123456789012:role/security-testing-audit-…"
                    autoComplete="off"
                  />
                  <button
                    type="button"
                    disabled={blocked || !roleArn}
                    onClick={() =>
                      void action("接続設定を保存しています", async () => {
                        const data = result(
                          await client.PUT(
                            "/v1/targets/{target_id}/aws-connection",
                            {
                              params: { path: { target_id: targetId } },
                              body: { role_arn: roleArn },
                            },
                          ),
                        );
                        setConnection(data);
                        setNotice(
                          "接続設定を保存しました。次に対象リソースを指定してください。",
                        );
                      })
                    }
                  >
                    接続設定を保存
                  </button>
                  <p className="hint">{connection.status}</p>
                </>
              )}
              <label htmlFor="audit-region">対象リージョン</label>
              <input
                id="audit-region"
                value={region}
                onChange={(e) => {
                  setRegion(e.target.value);
                  setAuthorized(false);
                }}
                disabled={blocked}
              />
              {kinds.map((kind) => (
                <div key={kind}>
                  <label htmlFor={`audit-${kind}`}>
                    {fields[kind][0]}（最大3個・改行区切り）
                  </label>
                  <textarea
                    id={`audit-${kind}`}
                    rows={2}
                    placeholder={fields[kind][1]}
                    value={resources[kind] || ""}
                    onChange={(e) => {
                      setResources({ ...resources, [kind]: e.target.value });
                      setAuthorized(false);
                    }}
                    disabled={blocked}
                  />
                </div>
              ))}
            </div>
          )}
          <div className="execution-manifest">
            <h3>実行する範囲</h3>
            <p className="target-url">
              {targetUrl || "診断対象を選択してください"}
            </p>
            <p>
              {info.title}：
              {selectedChecks
                .map((c) => current?.checks?.[c] || c)
                .join("、") || "検査未選択"}
            </p>
            {profile === "network" && selectedChecks.includes("ports") && (
              <p>TCP：{ports.join(", ") || "未選択"}</p>
            )}
            {savedConnection.error && (
              <p role="alert">
                AWS接続設定の取得に失敗しました。{savedConnection.error.message}
              </p>
            )}
            {aws && (
              <p>リージョン：{region}。指定したリソースだけを読み取ります。</p>
            )}
            {profile !== "web" && (
              <label className="check-option">
                <input
                  type="checkbox"
                  checked={authorized}
                  disabled={blocked}
                  onChange={(e) => setAuthorized(e.target.checked)}
                />
                この対象と選択した検査範囲について、実施する権限・許可があります
              </label>
            )}
          </div>
          <button
            disabled={
              blocked ||
              !targetId ||
              (profile !== "web" && !authorized) ||
              !selectedChecks.length ||
              (profile === "network" &&
                selectedChecks.includes("ports") &&
                !ports.length) ||
              (aws && !connection?.role_arn)
            }
          >
            {info.title}を開始 →
          </button>
        </form>
      )}
      {busy && (
        <p role="status" className="operation-status">
          <span className="spinner small" aria-hidden="true" />
          {busy}
        </p>
      )}
      {error && (
        <p role="alert" className="notice error">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="notice success">
          {notice}
        </p>
      )}
    </div>
  );
}
