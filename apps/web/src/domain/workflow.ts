export const terminalStates = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);
export function isActive(state?: string): boolean {
  return Boolean(state && !terminalStates.has(state));
}
export function stateLabel(state?: string): string {
  return (
    (
      {
        QUEUED: "受付済み・順番待ち",
        RUNNING: "診断を実行中",
        CANCEL_REQUESTED: "キャンセル処理中",
        CANCELLED: "キャンセル済み",
        FAILED: "診断に失敗",
        SUCCEEDED: "診断完了",
      } as Record<string, string>
    )[state || ""] || "未実行"
  );
}
export function nextAction(hasTarget: boolean): string {
  if (!hasTarget) return "診断したい公開サイトのURLを登録してください。";
  return "診断の準備ができました。「診断を開始」を押してください。";
}
