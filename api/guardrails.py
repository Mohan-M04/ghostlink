def check_context(context, accounts, cycles):
    """
    Check for factors that could cause false positives.
    This function does not decide whether someone is guilty.
    """
    penalties = 0
    notes = []

    # Current service contract uses "indicators".
    indicators = context.get("indicators", [])

    if not indicators:
        notes.append(
            "No threat-feed indicator was returned. "
            "This does not prove the IP is safe."
        )

    # Many accounts sharing an IP may indicate public Wi-Fi,
    # a college network, or carrier NAT.
    account_count = accounts.get("total_matching", 0)

    if account_count >= 25:
        penalties += 15
        notes.append(
            "Many accounts share this IP. "
            "Check for shared network infrastructure."
        )

    # Do not invent an age when the service doesn't provide one.
    for indicator in indicators:
        age_days = indicator.get("age_days")

        if age_days is not None and age_days > 180:
            penalties += 15
            notes.append(
                "A threat indicator is older than 180 days. "
                "Verify that it is still relevant."
            )

    if not cycles.get("cycles"):
        notes.append(
            "No transaction cycle was found in the queried data."
        )

    notes.append(
        "A shared IP or device alone does not prove "
        "that accounts have the same owner."
    )

    return {
        "penalties": min(40, penalties),
        "notes": notes,
        "human_review_required": True,
    }