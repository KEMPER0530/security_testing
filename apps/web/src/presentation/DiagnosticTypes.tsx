import { diagnosticProfiles, type ProfileId } from "../domain/diagnostics";
export function DiagnosticTypes({
  selected,
  onSelect,
  historyCounts,
}: {
  selected: ProfileId;
  onSelect: (value: ProfileId) => void;
  historyCounts?: Partial<Record<ProfileId, number>>;
}) {
  return (
    <div className="diagnostic-types" role="group" aria-label="診断の種類">
      {Object.entries(diagnosticProfiles).map(([key, info]) => (
        <button
          key={key}
          type="button"
          className={`diagnostic-type ${selected === key ? "selected" : ""}`}
          aria-label={info.title}
          aria-describedby={`diagnostic-type-${key}`}
          aria-pressed={selected === key}
          onClick={() => onSelect(key as ProfileId)}
        >
          <span className="diagnostic-type-title">
            {info.title}
            <span aria-hidden="true">{selected === key ? "●" : "○"}</span>
          </span>
          <small id={`diagnostic-type-${key}`}>{info.summary}</small>
          {historyCounts && (
            <span className="diagnostic-history-count">
              この対象の履歴 {historyCounts[key as ProfileId] || 0}件
            </span>
          )}
        </button>
      ))}
    </div>
  );
}
