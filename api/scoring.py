import math


# Evidence reliability depends on its tier.
TIER_WEIGHT = {
    "OBSERVED": 1.0,
    "DERIVED": 0.7,
    "INFERRED": 0.4,
}


def edge_strength(tier, reliability, age_days, degree):
    """
    Calculate the strength of one relationship in the graph.

    OBSERVED = directly recorded evidence
    DERIVED  = calculated from available evidence
    INFERRED = a possible connection, not directly confirmed
    """

    if tier not in TIER_WEIGHT:
        raise ValueError(f"Invalid evidence tier: {tier}")

    reliability = max(0.0, min(1.0, float(reliability)))
    age_days = max(0, int(age_days))
    degree = max(0, int(degree))

    # Older evidence receives less weight.
    recency = max(0.1, math.exp(-age_days / 180))

    # Common, heavily connected nodes provide weaker evidence.
    hub_weight = 1 / math.log2(2 + degree)

    return round(
        TIER_WEIGHT[tier]
        * reliability
        * recency
        * hub_weight,
        4,
    )


def calculate_score(signals, penalties=0):
    """
    Calculate an investigation-priority score from 0 to 100.

    This is NOT a probability that an account is guilty.
    """

    allowed_signals = ("ip_flag", "shared_device", "txn_cycle")

    values = []

    for name in allowed_signals:
        if name in signals:
            value = float(signals[name])

            if not 0 <= value <= 1:
                raise ValueError(
                    f"{name} must be between 0 and 1"
                )

            values.append(value)

    # No signals means there is no positive score evidence.
    remaining = 1.0

    for value in values:
        remaining *= 1 - value

    penalties = max(0.0, min(40.0, float(penalties)))

    score = round(
        max(0.0, min(100.0, 100 * (1 - remaining) - penalties)),
        1,
    )

    # Provisional bands for the hackathon demo.
    if score < 40:
        band = "monitor"
        action = "monitor"
    elif score < 70:
        band = "investigate"
        action = "investigate"
    elif score < 85:
        band = "human_review"
        action = "request_review"
    else:
        band = "urgent_human_review"
        action = "escalate_for_human_review"

    return {
        "score": score,
        "band": band,
        "recommended_action": action,
        "is_probability_of_guilt": False,
    }