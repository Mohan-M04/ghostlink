def check_context(context, accounts, shared_devices, cycles):
    penalties = []
    innocent_explanations = []
    caps = []
    conflicts = []
    
    indicators = context.get("indicators", [])
    degree = context.get("degree", 0)
    is_public = context.get("is_public_network", False)
    
    # 1. Public network / High hub degree
    if degree >= 25 or is_public:
        penalties.append({
            "type": "PUBLIC_NETWORK",
            "deduction": 25,
            "reason": f"High IP degree ({degree}) indicates shared public Wi-Fi or NAT."
        })
        innocent_explanations.append(
            f"This IP is used by {degree} accounts, typical for public Wi-Fi or carrier NAT. Shared IP alone is never proof of fraud."
        )
        
    # 2. Conflicting threat feeds
    severities = {i.get("severity") for i in indicators if i.get("severity")}
    if len(severities) > 1:
        conflicts.append("Contradictory intelligence feeds: reports show conflicting risk levels.")
        penalties.append({
            "type": "CONFLICTING_SOURCES",
            "deduction": 15,
            "reason": "Contradictory intelligence feeds reduce confidence."
        })
        
    # 3. Stale indicator check
    for ind in indicators:
        if ind.get("id") == "TI-STALE" or "stale" in str(ind.get("note", "")).lower():
            penalties.append({
                "type": "STALE_INDICATOR",
                "deduction": 20,
                "reason": "Threat indicator is older than 180 days."
            })
            innocent_explanations.append("Threat indicator is stale; historic reputation may no longer apply.")
            
    # 4. Check infrastructure-only caps
    has_cycle = bool(cycles and cycles.get("cycles"))
    has_shared_dev = bool(shared_devices and shared_devices.get("devices"))
    if not has_cycle and not has_shared_dev:
        caps.append("SINGLE_INFRA_SIGNAL")
        innocent_explanations.append("Only an infrastructure indicator was found without transaction or device links.")
        
    # 5. Family device decoy check
    if has_shared_dev and not has_cycle and len(shared_devices.get("devices", [])) == 1:
        dev = shared_devices["devices"][0]
        if dev.get("degree", 0) <= 4:
            innocent_explanations.append(
                f"Device {dev.get('id')} is shared by {dev.get('degree')} accounts with zero circular transactions, consistent with a family device."
            )
            
    return {
        "penalties": penalties,
        "innocent_explanations": innocent_explanations,
        "conflicts": conflicts,
        "caps": caps
    }
