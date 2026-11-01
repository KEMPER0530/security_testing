import { InfoTooltip } from "./InfoTooltip";
import { AttackAnalysis } from "./AttackAnalysis";
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
              href="https://www.first.org/cvss/v4.0/specification-document"
              target="_blank"
              rel="noreferrer"
            >
              CVSS v4.0の仕様 ↗
            </a>
          </details>
        </>
      )}
    </div>
  );
}
export function Findings({ report }: { report: Item }) {
  return (
    <div className="report-content" data-testid="diagnosis-report">
      <div className="report-summary">
        <div>
          <small>最高深刻度（暫定）</small>
          <strong>
            {report.summary.highest_severity ||
              (report.summary.configuration_count ? "未評価" : "検出なし")}
          </strong>
        </div>
        <div>
          <small>設定改善候補</small>
          <strong>
            {report.summary.configuration_count}
            <span>件</span>
          </strong>
        </div>
        <div>
          <small>CVSS参考評価</small>
          <strong>
            {report.summary.reference_assessed_count ?? 0}
            <span>件</span>
          </strong>
        </div>
      </div>
      <p className="muted">
        深刻度は公開ページの設定観測による暫定評価です。CVSSは、追加の攻撃条件が成立すると仮定した参考スコアです。攻撃の成立や情報漏えいを確認した数値ではありません。各項目の「?」で説明と判定根拠を確認できます。
      </p>
      <p className="muted">
        CVSS深刻度別（参考評価を含む）：
        {Object.entries(report.summary.cvss_severity_counts)
          .map(([name, count]) => `${name} ${count}件`)
          .join(" / ")}
        。採点対象外の改善候補：{report.summary.cvss_not_applicable_count ?? 0}
        件
        {report.summary.unassessed_count > 0
          ? `。未評価：${report.summary.unassessed_count}件`
          : ""}
      </p>
      {report.attack_analysis && (
        <AttackAnalysis analysis={report.attack_analysis} />
      )}
      <h3 className="checks-heading">チェック項目ごとの結果</h3>
      <div className="findings-table">
        <table>
          <thead>
            <tr>
              <th>チェック項目</th>
              <th>判定</th>
              <th>深刻度（暫定）</th>
              <th>CVSS v4.0</th>
              <th>対応優先度</th>
              <th>根拠・改善方法</th>
            </tr>
          </thead>
          <tbody>
            {report.findings.map((f: Item) => (
              <tr key={f.rule_id}>
                <td>
                  <Title finding={f} />
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
        {report.findings.map((f: Item) => (
          <article className="finding-card" key={f.rule_id}>
            <div className="finding-title">
              <h3>
                <Title finding={f} />
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
                <dt>CVSS v4.0</dt>
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
      <p className="coverage">
        診断範囲：{report.coverage.scope}。対象外：
        {report.coverage.not_tested.join("、")}
        。問題の未検出は安全保証ではありません。
      </p>
    </div>
  );
}
