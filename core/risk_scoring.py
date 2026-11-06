def calculate_risk_score(severity: str, confidence: int) -> float:
    weights = {
        "Critical": 10.0,
        "High": 8.0,
        "Medium": 5.0,
        "Low": 2.0,
        "Informational": 1.0
    }
    weight = weights.get(severity, 1.0)
    conf_factor = max(0, min(100, confidence)) / 100.0
    raw_score = weight * conf_factor * 10.0
    return round(min(100.0, max(0.0, raw_score)), 1)
