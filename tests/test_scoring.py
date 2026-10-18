from api.scoring import edge_strength, calculate_score

print("Edge strength:")
print(edge_strength("OBSERVED", 0.9, 2, 3))

print("\nInvestigation score:")
result = calculate_score({
    "ip_flag": 0.8,
    "shared_device": 0.5,
    "txn_cycle": 0.7,
})

print(result)

print("\nEmpty signals:")
print(calculate_score({}))