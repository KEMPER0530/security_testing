from cvss import CVSS4
from site_diagnostics.domain.model import Rejected, severity


class CvssCalculator:
    def calculate(self, vector: str, rationale: dict) -> dict:
        if not vector.startswith("CVSS:4.0/") or not rationale:
            raise Rejected("CVSS v4.0のベクトルと根拠が必要です")
        try:
            value = float(CVSS4(vector).scores()[0])
        except Exception as exc:
            raise Rejected("CVSSベクトルが不正です") from exc
        metrics = {part.split(":")[0]: part.split(":")[1] for part in vector.split("/")[1:]}
        if any(key not in rationale or not rationale[key].strip() for key in metrics):
            raise Rejected("各メトリクスの根拠が必要です")
        environmental = any(k.startswith("M") or k in ("CR", "IR", "AR") for k in metrics)
        threat = "E" in metrics
        return {
            "version": "4.0",
            "vector": vector,
            "score": value,
            "severity": severity(value),
            "type": "CVSS-B" + ("T" if threat else "") + ("E" if environmental else ""),
            "rationale": rationale,
            "calculator": "cvss==3.6",
        }
