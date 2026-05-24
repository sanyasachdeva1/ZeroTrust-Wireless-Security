SEVERITY_BASE_SCORE = {
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 75,
    "CRITICAL": 95,
}


def score_event(severity, modifiers=None):
    score = SEVERITY_BASE_SCORE.get(severity.upper(), 50)

    for modifier in modifiers or []:
        score += modifier

    return max(0, min(score, 100))


def severity_from_score(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
