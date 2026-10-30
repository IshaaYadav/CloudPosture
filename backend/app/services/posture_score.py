"""Security Posture Score calculation service."""

import logging
from typing import Optional

from app.checks.base import CheckResult, CheckStatus
from app.schemas.aws import PostureScore

logger = logging.getLogger(__name__)


def calculate_posture_score(check_results: list[CheckResult] | list[dict]) -> PostureScore:
    """Calculate the overall security posture score.

    Formula:
        Score = PASS / (PASS + FAIL) * 100

    Rules:
        - Exclude ERROR checks from the denominator.
        - If (PASS + FAIL) == 0, score is None and rating is 'N/A'.
        - Ratings:
            >= 80%: Excellent (A)
            >= 60%: Good (B)
            >= 40%: Fair (C)
            < 40%: Poor (F)

    Args:
        check_results: List of CheckResult objects or dicts.

    Returns:
        PostureScore instance.
    """
    total = len(check_results)
    passed = 0
    failed = 0
    errors = 0

    for res in check_results:
        status = res.status if hasattr(res, "status") else res.get("status", "")
        if status == CheckStatus.PASS.value:
            passed += 1
        elif status == CheckStatus.FAIL.value:
            failed += 1
        elif status == CheckStatus.ERROR.value:
            errors += 1
        else:
            errors += 1

    evaluated = passed + failed
    score: Optional[float] = None
    rating = "N/A"

    if evaluated > 0:
        score = round((passed / evaluated) * 100.0, 1)
        if score >= 80.0:
            rating = "Excellent"
        elif score >= 60.0:
            rating = "Good"
        elif score >= 40.0:
            rating = "Fair"
        else:
            rating = "Poor"

    logger.info(
        f"Posture score calculated: passed={passed}, failed={failed}, errors={errors}, score={score}% ({rating})"
    )

    return PostureScore(
        total_checks=total,
        passed=passed,
        failed=failed,
        errors=errors,
        score=score,
        rating=rating,
    )

