from statistics import mean, pstdev


def z_score_deviation(baseline: list[float], observed: float) -> dict:
    if not baseline:
        return {"deviation": "unknown", "confidence": 0}
    avg = mean(baseline)
    deviation = pstdev(baseline) or 1
    score = abs(observed - avg) / deviation
    return {
        "baseline": round(avg, 2),
        "observed": observed,
        "deviation": f"{round(score, 2)} sigma",
        "confidence": min(99, int(score * 18)),
    }


def isolation_forest_ready() -> bool:
    try:
        from sklearn.ensemble import IsolationForest  # noqa: F401

        return True
    except Exception:
        return False
