import math

TIER_WEIGHT = {
    "OBSERVED": 1.0,
    "DERIVED": 0.7,
    "INFERRED": 0.4,
}

def edge_strength(tier, reliability, age_days, degree):
    tier = tier if tier in TIER_WEIGHT else "OBSERVED"
    reliability = max(0.0, min(1.0, float(reliability)))
    age_days = max(0, int(age_days))
    degree = max(0, int(degree))
    recency = max(0.05, 0.5 ** (age_days / 180))
    hub_weight = 1.0 / math.log2(2 + degree)
    return round(TIER_WEIGHT[tier] * reliability * recency * hub_weight, 4)

def calculate_score(signals, penalties, caps):
    strengths = sorted([s.get("strength", 0.0) for s in signals], reverse=True)
    s1 = strengths[0] if len(strengths) > 0 else 0.0
    s2 = strengths[1] if len(strengths) > 1 else 0.0
    s3 = strengths[2] if len(strengths) > 2 else 0.0
    
    combined_raw = s1 + 0.5 * s2 * (1.0 - s1) + 0.25 * s3 * (1.0 - s1)
    score_pre = 100.0 * combined_raw
    total_penalties = sum(p.get("deduction", 0) for p in penalties)
    final_score = int(round(max(0, min(100, score_pre - total_penalties))))
    
    if "SINGLE_INFRA_SIGNAL" in caps and final_score > 39:
        final_score = 39
    if "INFERRED_ONLY" in caps and final_score > 39:
        final_score = 39
        
    if final_score < 40:
        band = "monitor"
        action = "Review available evidence"
    elif final_score < 70:
        band = "investigate"
        action = "WATCHLIST"
    elif final_score < 85:
        band = "human_review"
        action = "MANUAL_REVIEW"
    else:
        band = "urgent_review"
        action = "STEP_UP_VERIFICATION"
        
    return {
        "score": final_score,
        "band": band,
        "recommended_action": action,
        "score_breakdown": {
            "signals": signals,
            "combined_raw": round(combined_raw, 4),
            "penalties": penalties,
            "caps": caps,
            "final": final_score
        }
    }
