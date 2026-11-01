export function severityLabel(score: number | null | undefined): string {
  if (score == null) return "未評価";
  if (score === 0) return "なし";
  if (score < 4) return "低";
  if (score < 7) return "中";
  if (score < 9) return "高";
  return "緊急";
}
