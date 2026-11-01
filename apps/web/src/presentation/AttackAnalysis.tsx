type Item = Record<string, any>;
export function AttackAnalysis({ analysis }: { analysis: Item }) {
  return (
    <section
      className="attack-analysis"
      aria-label="想定される攻撃と注意が必要な場所"
    >
      <div className="analysis-heading">
        <div>
          <span className="eyebrow">ATTACK SCENARIOS</span>
          <h3>どこに注意が必要？</h3>
        </div>
        <span className="badge">設定に基づく分析</span>
      </div>
      <p>{analysis.notice}</p>
      <p className="muted">{analysis.scope}</p>
      {analysis.target_url && (
        <p className="analysis-target">分析対象：{analysis.target_url}</p>
      )}
      <div
        className="attack-breakdown"
        aria-label="攻撃の種類ごとの設定改善候補の内訳"
      >
        {analysis.items.map((item: Item) => (
          <div key={item.id}>
            <span>{item.title}</span>
            <b>{item.finding_count}件</b>
          </div>
        ))}
      </div>
      {!analysis.items.length && (
        <p className="empty">
          今回確認した設定には、この分析の対象となる改善候補がありませんでした。下記の未検証項目を含め、サイト全体の安全を保証するものではありません。
        </p>
      )}
      <div className="attack-cards">
        {analysis.items.map((item: Item) => (
          <article className="attack-card" key={item.id}>
            <div className="analysis-heading">
              <h4>{item.title}</h4>
              <span
                className={`badge ${item.severity === "高" ? "warning" : ""}`}
              >
                注意度（暫定）：{item.severity}
              </span>
            </div>
            <p className="attack-location">
              <b>注意が必要な場所</b>
              {item.location}
            </p>
            <p>{item.explanation}</p>
            <p>
              <b>起こり得る被害：</b>
              {item.possible_impact}
            </p>
            <details>
              <summary>判断した根拠と、攻撃が成立する条件</summary>
              <p>{item.conditions}</p>
              <ul>
                {item.evidence.map((e: Item) => (
                  <li key={e.rule_id}>
                    <b>{e.title}：</b>
                    {e.observed}
                  </li>
                ))}
              </ul>
            </details>
            <div className="attack-actions">
              <b>まず取り組む対策</b>
              <ul>
                {item.actions.map((action: string) => (
                  <li key={action}>{action}</li>
                ))}
              </ul>
            </div>
          </article>
        ))}
      </div>
      <details className="not-evaluated">
        <summary>今回の診断で評価していない攻撃</summary>
        <dl>
          {analysis.not_evaluated.map((item: Item) => (
            <div key={item.title}>
              <dt>{item.title}</dt>
              <dd>{item.reason}</dd>
            </div>
          ))}
        </dl>
        <p>
          これらは「問題なし」という意味ではありません。必要に応じて、入力処理・認証後の操作・AWS設定等の追加診断を行ってください。
        </p>
      </details>
    </section>
  );
}

export function AiAnalysisPending() {
  return (
    <section className="ai-analysis-pending" aria-label="AI分析">
      <div>
        <div className="analysis-heading">
          <h3>AI分析</h3>
          <span className="badge">工事中</span>
        </div>
        <p>
          AIが診断結果を読み解き、対策の検討を支援する機能を準備しています。
        </p>
        <small>
          現在、この機能から外部AIへ診断データを送ることはありません。
        </small>
      </div>
      <button disabled title="準備ができるまで利用できません">
        AI分析を実行（準備中）
      </button>
    </section>
  );
}
