def simulate_attack(package_name, risk_score):

    attacks = []

    if risk_score >= 70:
        attacks.append("Remote Code Execution possible")
        attacks.append("Supply chain injection risk")
        impact = "Critical"

    elif risk_score >= 40:
        attacks.append("Privilege escalation risk")
        impact = "Medium"

    else:
        attacks.append("Minimal exploit surface")
        impact = "Low"

    return {
        "impact_level": impact,
        "simulated_attacks": attacks
    }