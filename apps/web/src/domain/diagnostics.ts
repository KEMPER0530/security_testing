export const diagnosticProfiles = {
  web: {
    title: "Web診断",
    summary: "公開ページのHTTPS・保護設定を確認",
    result: "ページの保護設定",
    scope: "公開ページの保護設定と静的HTML",
  },
  pentest: {
    title: "ペネトレーション（限定検証）",
    summary: "検査項目を選び、Webの応答を検証",
    result: "HTTP検証と保護設定",
    scope: "選択したHTTP検証。実際の侵入・権限昇格は対象外",
  },
  network: {
    title: "ネットワーク診断",
    summary: "DNS・TCPポート・TLSの接続状態を確認",
    result: "接続先・ポート・通信の状態",
    scope: "登録ホストのDNS・選択ポート・Web通信",
  },
  host: {
    title: "AWSホスト診断",
    summary: "EC2のOS情報・収集状態・既知の脆弱性を確認",
    result: "EC2の収集状態と既知の脆弱性",
    scope: "指定EC2のSSM・Inspector収集済み情報",
  },
  cloud: {
    title: "AWSクラウド診断",
    summary: "S3・通信許可・操作記録などのAWS設定を確認",
    result: "AWSリソースの設定",
    scope: "選択したAWSリソースとアカウント設定",
  },
} as const;
export type ProfileId = keyof typeof diagnosticProfiles;
type Item = Record<string, any>;
export function isProfile(value: unknown): value is ProfileId {
  return typeof value === "string" && Object.hasOwn(diagnosticProfiles, value);
}
export function profileOfJob(job?: Item | null): ProfileId | null {
  const value = job?.plan?.profile ?? "web";
  return isProfile(value) ? value : null;
}
export function profileOfReport(report: Item): ProfileId | null {
  const value = report.plan?.profile ?? report.coverage?.profile ?? "web";
  if (
    report.plan?.profile &&
    report.coverage?.profile &&
    report.plan.profile !== report.coverage.profile
  )
    return null;
  return isProfile(value) ? value : null;
}
export function findingContext(f: Item): string {
  const d = f.details || {};
  const parts: string[] = [];
  if (d.resource)
    parts.push(d.resource === "account" ? "AWSアカウント" : String(d.resource));
  if (d.vulnerability_id) parts.push(String(d.vulnerability_id));
  if (d.port) parts.push(`TCP ${d.port}`);
  if (d.connection)
    parts.push(
      (
        {
          open: "TCP接続可",
          refused: "接続拒否",
          unknown: "接続状態は確認不能",
        } as Record<string, string>
      )[d.connection] || "接続状態は確認不能",
    );
  if (d.method) parts.push(String(d.method));
  if (d.http_status) parts.push(`HTTP ${d.http_status}`);
  if (d.allowed_methods?.length)
    parts.push(`許可表示：${d.allowed_methods.join(", ")}`);
  return parts.join(" / ");
}
export function findingGroups(profile: ProfileId, findings: Item[]) {
  const definitions: [string, string, (f: Item) => boolean][] =
    profile === "network"
      ? [
          [
            "ports",
            "TCPポートの接続結果",
            (f) => f.rule_id.startsWith("PORT_"),
          ],
          ["transport", "DNS・通信・証明書", () => true],
        ]
      : profile === "pentest"
        ? [
            [
              "http",
              "HTTPの限定検証",
              (f) => ["CORS", "METHODS", "TRACE"].includes(f.rule_id),
            ],
            ["headers", "保護設定（Web診断と共通）", () => true],
          ]
        : profile === "host"
          ? [
              [
                "inventory",
                "OS情報・SSMの収集状態",
                (f) =>
                  f.details?.check === "inventory" ||
                  f.rule_id.startsWith("AWS_INVENTORY"),
              ],
              [
                "vulnerabilities",
                "Inspectorが検出した既知の脆弱性",
                (f) =>
                  f.kind === "vulnerability" ||
                  /^AWS_INSPECTOR_[a-f0-9]{24}/.test(f.rule_id),
              ],
              ["collection", "Inspectorの収集範囲・取得状態", () => true],
            ]
          : profile === "cloud"
            ? [
                [
                  "identity",
                  "アカウントの保護",
                  (f) =>
                    f.details?.check === "root_mfa" ||
                    f.rule_id.startsWith("AWS_ROOT_MFA"),
                ],
                [
                  "storage",
                  "S3の公開防止・暗号化",
                  (f) =>
                    f.details?.check === "s3" || f.rule_id.startsWith("AWS_S3"),
                ],
                [
                  "access",
                  "通信の許可設定",
                  (f) =>
                    f.details?.check === "security_groups" ||
                    f.rule_id.startsWith("AWS_SG_") ||
                    f.rule_id.startsWith("AWS_SECURITY_GROUPS"),
                ],
                ["audit", "操作記録・その他の設定", () => true],
              ]
            : [
                [
                  "communication",
                  "通信の保護",
                  (f) =>
                    ["HTTPS", "TLS", "HSTS", "MIXED", "REDIRECT"].includes(
                      f.rule_id,
                    ),
                ],
                ["cookies", "Cookieの保護", (f) => f.rule_id === "COOKIE"],
                ["page", "ページの保護設定", () => true],
              ];
  const remaining = new Set(findings);
  return definitions
    .map(([key, title, test]) => {
      const rows = findings.filter((f) => remaining.has(f) && test(f));
      rows.forEach((f) => remaining.delete(f));
      return { key, title, findings: rows };
    })
    .filter((g) => g.findings.length);
}
export function profileMetric(profile: ProfileId, report: Item) {
  const rows: Item[] = report.findings;
  if (profile === "network")
    return {
      label: "TCPポートの検査項目",
      value: rows.filter((f) => f.rule_id.startsWith("PORT_")).length,
    };
  if (profile === "pentest")
    return {
      label: "HTTPの限定検証項目",
      value: rows.filter((f) =>
        ["CORS", "METHODS", "TRACE"].includes(f.rule_id),
      ).length,
    };
  if (profile === "host")
    return {
      label: "既知脆弱性の検出",
      value: rows.filter(
        (f) =>
          f.kind === "vulnerability" ||
          /^AWS_INSPECTOR_[a-f0-9]{24}/.test(f.rule_id),
      ).length,
    };
  if (profile === "cloud")
    return { label: "設定の検査項目", value: rows.length };
  return {
    label: "CVSS参考評価",
    value: report.summary.reference_assessed_count ?? 0,
  };
}
