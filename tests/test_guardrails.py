from api.guardrails import check_context

result = check_context(
    context={
        "flags": [
            {
                "source": "simulated_feed",
                "age_days": 250
            }
        ]
    },
    accounts={
        "total_before_limit": 40
    },
    cycles={
        "cycles": []
    }
)

print(result)