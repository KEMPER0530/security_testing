import { InfoTooltip } from "./InfoTooltip";
import { AttackAnalysis } from "./AttackAnalysis";
import {
  diagnosticProfiles,
  profileOfReport,
  profileMetric,
  findingGroups,
  findingContext,
  type ProfileId,
} from "../domain/diagnostics";
type Item = Record<string, any>;
function Title({ finding: f }: { finding: Item }) {
  return (
    <span className="check-title">
      {f.title}
      <InfoTooltip
        label={`${f.title}の説明`}
        text={`${f.explanation || "保存済みのチェック結果です。"}\nなぜ必要？ ${f.purpose || "詳細な確認が必要です。"}`}
      />
    </span>
  );
}
function Basis({ finding: f }: { finding: Item }) {
  return (
    <div>
      {f.evidence}
      <InfoTooltip
        label={`${f.title}の判定根拠`}
        text={f.criteria || "この旧チェックには判定基準の記録がありません。"}
      />
      <small>{f.fix}</small>
      {f.reference && (
        <a
          className="reference-link"
          href={f.reference}
          target="_blank"
          rel="noreferrer"
        >
          チェックの出典 ↗
        </a>
      )}
    </div>
  );
}
function Cvss({ finding: f }: { finding: Item }) {
  const value = f.cvss;
  const reference = value?.assessment === "scenario_reference";
  return (
    <div className="cvss-value">
      <span>
        {value
          ? `${Number(value.score).toFixed(1)}${reference ? "（参考）" : ""}`
          : f.cvss_status || "未評価"}
      </span>
      <InfoTooltip
        label={`${f.title}のCVSS評価根拠`}
        text={`${f.cvss_reason || "評価根拠の記録がありません。"}${value?.scenario ? `\n採点時の仮定：${value.scenario}` : ""}`}
      />
      {value && (
        <>
          <small>
            {value.severity} / CVSS {value.version}
          </small>
          <details className="cvss-details">
            <summary>採点の前提・指標</summary>
            <p>{value.scenario}</p>
            <code>{value.vector}</code>
            <dl>
              {Object.entries(value.rationale || {}).map(([key, reason]) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd>{String(reason)}</dd>
                </div>
              ))}
            </dl>
            <a
              href={
                value.version === "4.0"
                  ? "https://www.first.org/cvss/v4.0/specification-document"
                  : "https://www.first.org/cvss/v3.1/specification-document"
              }
              target="_blank"
              rel="noreferrer"
            >
              CVSSの仕様 ↗
            </a>
          </details>
        </>
      )}
    </div>
  );
}
function FindingRows({ findings }: { findings: Item[] }) {
  return (
    <>
      {" "}
      <div className="findings-table">
        <table>
          <thead>
            <tr>
              <th>チェック項目</th>
              <th>判定</th>
              <th>深刻度（暫定）</th>
              <th>CVSS</th>
              <th>対応優先度</th>
              <th>根拠・改善方法</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f: Item) => (
              <tr key={f.rule_id}>
                <td>
                  <Title finding={f} />
                  {findingContext(f) && (
                    <small className="finding-context">
                      {findingContext(f)}
                    </small>
                  )}
                </td>
                <td>
                  <span
                    className={`badge ${f.status === "問題を検出" ? "warning" : ""}`}
                  >
                    {f.status}
                  </span>
                </td>
                <td>
                  <span
                    className={`badge ${["高", "緊急"].includes(f.severity) ? "warning" : ""}`}
                  >
                    {f.severity || "未評価"}
                  </span>
                  <small>{f.severity_basis || "旧レポートのため未評価"}</small>
                </td>
                <td>
                  <Cvss finding={f} />
                </td>
                <td>{f.priority}</td>
                <td>
                  <Basis finding={f} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="finding-cards">
        {findings.map((f: Item) => (
          <article className="finding-card" key={f.rule_id}>
            <div className="finding-title">
              <h3>
                <Title finding={f} />
                {findingContext(f) && (
                  <small className="finding-context">{findingContext(f)}</small>
                )}
              </h3>
              <span
                className={`badge ${f.status === "問題を検出" ? "warning" : ""}`}
              >
                {f.status}
              </span>
            </div>
            <dl className="finding-metrics">
              <div>
                <dt>深刻度（暫定）</dt>
                <dd>{f.severity || "未評価"}</dd>
              </div>
              <div>
                <dt>CVSS</dt>
                <dd>
                  <Cvss finding={f} />
                </dd>
              </div>
              <div>
                <dt>対応優先度</dt>
                <dd>{f.priority}</dd>
              </div>
            </dl>
            <Basis finding={f} />
          </article>
        ))}
      </div>
    </>
  );
}
export function Findings({
  report,
  expectedProfile,
}: {
  report: Item;
  expectedProfile?: ProfileId;
}) {
  const profile = profileOfReport(report);
  if (!profile || (expectedProfile && profile !== expectedProfile))
    return (
      <p className="notice error" role="alert">
        診断種類が一致しないため、この結果は表示できません。
      </p>
    );
  const info = diagnosticProfiles[profile];
  const metric = profileMetric(profile, report);
  const uncertain = report.findings.filter((f: Item) =>
    ["確認不能", "未実施"].includes(f.status),
  ).length;
  const plan = report.plan || report.coverage;
  const checkLabels: Record<string, string> = {
    headers: "公開ページの保護設定",
    dns: "DNS",
    ports: "TCP接続",
    tls: "Web通信・TLS",
    cors: "別サイトへの読み取り許可",
    methods: "許可メソッド",
    trace: "TRACE応答",
    inventory: "SSM収集状態",
    inspector: "Inspectorの既知脆弱性",
    root_mfa: "ルートMFA",
    s3: "S3設定",
    security_groups: "通信許可設定",
    cloudtrail: "操作記録",
  };
  return (
    <div
      className="report-content"
      data-testid="diagnosis-report"
      data-result-profile={profile}
    >
      <div className="result-identity">
        <span className="badge">{info.title}の保存結果</span>
        <h3>{info.result}</h3>
        <p>{report.coverage.scope}</p>
        {plan.checks?.length > 0 && (
          <p>
            実行した検査：
            {plan.checks
              .map((key: string) => checkLabels[key] || key)
              .join("、")}
          </p>
        )}
        {profile === "network" && plan.ports?.length > 0 && (
          <p>対象TCPポート：{plan.ports.join(", ")}</p>
        )}
        {(profile === "host" || profile === "cloud") && (
          <>
            <p>対象リージョン：{plan.region || "記録なし"}</p>
            {Object.entries(plan.resources || {}).map(([kind, values]) => (
              <p key={kind}>
                {(
                  {
                    instances: "EC2",
                    buckets: "S3",
                    security_groups: "セキュリティグループ",
                    trails: "CloudTrail",
                  } as Record<string, string>
                )[kind] || kind}
                ：{(values as string[]).join(", ")}
              </p>
            ))}
          </>
        )}
      </div>
      <div className="report-summary">
        <div>
          <small>最高深刻度（観測範囲内）</small>
          <strong>
            {report.summary.highest_severity ||
              (report.summary.configuration_count ? "未評価" : "検出なし")}
          </strong>
        </div>
        <div>
          <small>検出候補</small>
          <strong>
            {report.summary.configuration_count}
            <span>件</span>
          </strong>
        </div>
        <div>
          <small>{metric.label}</small>
          <strong>
            {metric.value}
            <span>件</span>
          </strong>
        </div>
      </div>
      {uncertain > 0 && (
        <p className="notice result-uncertain">
          未実施・確認不能が{uncertain}
          件あります。確認できていない項目を「問題なし」として扱っていません。
        </p>
      )}
      <p className="muted">
        深刻度は今回の観測範囲に基づきます。CVSSの「参考」は追加条件を仮定した評価、提供元評価はInspectorなどの既知脆弱性の評価です。どちらも今回の攻撃成功を示すものではありません。「?」から説明と根拠を確認できます。
      </p>
      <p className="muted">
        CVSS深刻度別（参考評価を含む）：
        {Object.entries(report.summary.cvss_severity_counts || {})
          .map(([name, count]) => `${name} ${count}件`)
          .join(" / ")}
        。採点対象外の改善候補：{report.summary.cvss_not_applicable_count ?? 0}
        件
        {report.summary.unassessed_count > 0
          ? `。未評価：${report.summary.unassessed_count}件`
          : ""}
      </p>
      {profile === "web" && report.attack_analysis && (
        <AttackAnalysis analysis={report.attack_analysis} />
      )}
      {(profile === "web" || profile === "pentest") && report.ipa_checklist && (
        <details className="ipa-coverage">
          <summary>IPAの対策項目と確認できた範囲</summary>
          <p className="muted">
            IPA「安全なウェブサイトの作り方」を参照した対応表です。関連設定の観測は、各対策全体の合格を意味しません。
          </p>
          <div className="ipa-table">
            <table>
              <thead>
                <tr>
                  <th>IPA節・項目</th>
                  <th>今回の確認</th>
                  <th>追加で必要な確認</th>
                </tr>
              </thead>
              <tbody>
                {report.ipa_checklist.map((item: Item) => (
                  <tr key={item.section}>
                    <td>
                      <a href={item.source} target="_blank" rel="noreferrer">
                        {item.section} {item.title} ↗
                      </a>
                    </td>
                    <td>{item.coverage}</td>
                    <td>{item.additional_verification}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      {findingGroups(profile, report.findings).map((group) => (
        <section
          className="result-group"
          key={group.key}
          data-result-group={group.key}
        >
          <h3>
            {group.title}
            <span className="badge">{group.findings.length}項目</span>
          </h3>
          {profile === "pentest" && group.key === "headers" && (
            <p className="hint">
              この項目はWeb診断と同じ検査です。同じ設定を確認した場合は、同じ指摘になることがあります。追加のHTTP検証は上のグループに表示します。
            </p>
          )}
          <FindingRows findings={group.findings} />
        </section>
      ))}
      <p className="coverage">
        診断範囲：{report.coverage.scope}。今回検査していない内容：
        {(report.coverage.not_tested || []).join("、")}
        。問題の未検出は安全保証ではありません。
      </p>
    </div>
  );
}
