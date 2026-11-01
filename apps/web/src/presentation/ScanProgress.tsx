import { isActive, stateLabel } from "../domain/workflow";
export function ScanProgress({
  state,
  url,
  createdAt,
  loadingResults = false,
}: {
  state: string;
  url: string;
  createdAt?: string;
  loadingResults?: boolean;
}) {
  const active = isActive(state);
  const phase = state === "QUEUED" ? 0 : state === "SUCCEEDED" ? 2 : 1;
  return (
    <section
      className={`scan-progress ${active ? "is-running" : ""}`}
      aria-busy={active || loadingResults}
      data-testid="scan-progress"
    >
      <div className="progress-heading" role="status" aria-live="polite">
        {active || loadingResults ? (
          <span className="spinner" aria-hidden="true" />
        ) : (
          <span className="status-symbol" aria-hidden="true">
            {state === "SUCCEEDED" ? "✓" : state === "FAILED" ? "!" : "−"}
          </span>
        )}
        <div>
          <h3>
            {loadingResults ? "診断結果を取得しています" : stateLabel(state)}
          </h3>
          <p className="progress-url">{url}</p>
        </div>
      </div>
      <ol className="run-stages" aria-label="診断の進行状況">
        {["受付", "サイトを確認", "結果を表示"].map((label, index) => (
          <li
            key={label}
            className={
              index < phase ? "complete" : index === phase ? "current" : ""
            }
            aria-current={index === phase ? "step" : undefined}
          >
            <span>{index < phase ? "✓" : index + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      {active && (
        <>
          <div
            className="activity-track"
            role="progressbar"
            aria-label="診断処理の進行状況"
            aria-valuetext={stateLabel(state)}
          >
            <span />
          </div>
          <p className="muted">
            サーバー側で非同期に処理しています。この画面を離れても診断は続き、完了すると結果が自動表示されます。
          </p>
        </>
      )}
      {createdAt && (
        <small>受付：{new Date(createdAt).toLocaleString("ja-JP")}</small>
      )}
    </section>
  );
}
