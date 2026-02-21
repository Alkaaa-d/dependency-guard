"""
Dependency-Guard
Attack Simulation Engine
----------------------------------
Simulates potential attacker actions
if a dependency is compromised.
"""

from datetime import datetime

# ----------------------------------
# Attack Mapping Database
# ----------------------------------

ATTACK_MAP = {
    "web_framework": [
        "Remote Code Execution (RCE)",
        "Session Hijacking",
        "Cross-Site Scripting (XSS)",
        "Authentication Bypass",
        "Malicious Middleware Injection"
    ],
    "cryptography": [
        "Encryption Key Leakage",
        "Weak Hash Exploitation",
        "Man-in-the-Middle Attack",
        "Signature Forgery",
        "TLS Downgrade Attack"
    ],
    "database": [
        "Unauthorized Data Extraction",
        "Privilege Escalation",
        "Database Dump Attack",
        "SQL Injection",
        "Credential Harvesting"
    ],
    "network": [
        "API Token Interception",
        "Packet Sniffing",
        "Data Exfiltration",
        "Server-Side Request Forgery (SSRF)",
        "DNS Spoofing"
    ],
    "utility": [
        "Code Injection",
        "Dependency Backdoor Insertion",
        "Malicious Update Deployment",
        "Privilege Abuse",
        "Arbitrary File Execution"
    ]
}

# ----------------------------------
# Known Package Category Mapping
# ----------------------------------

PACKAGE_CATEGORIES = {
    "flask": "web_framework",
    "django": "web_framework",
    "fastapi": "web_framework",

    "cryptography": "cryptography",
    "pycrypto": "cryptography",
    "bcrypt": "cryptography",

    "sqlalchemy": "database",
    "pymysql": "database",
    "psycopg2": "database",

    "requests": "network",
    "urllib3": "network",
    "httpx": "network",
}


# ----------------------------------
# Classify Package
# ----------------------------------

def classify_package(package_name):
    package_name = package_name.lower()

    if package_name in PACKAGE_CATEGORIES:
        return PACKAGE_CATEGORIES[package_name]

    # Default fallback
    return "utility"


# ----------------------------------
# Impact Level Calculator
# ----------------------------------

def calculate_impact_level(category, risk_score=None):
    """
    Determine impact level based on category and optional risk score
    """

    high_impact_categories = ["cryptography", "database"]
    medium_impact_categories = ["web_framework", "network"]

    if category in high_impact_categories:
        return "Critical Impact"

    if category in medium_impact_categories:
        return "High Impact"

    if risk_score:
        if risk_score > 70:
            return "High Impact"
        elif risk_score > 40:
            return "Moderate Impact"

    return "Moderate Impact"


# ----------------------------------
# Risk-Based Attack Filtering
# ----------------------------------

def filter_attacks_by_risk(attacks, risk_score=None):
    """
    If risk score is low, reduce number of simulated attacks
    """

    if risk_score is None:
        return attacks

    if risk_score < 30:
        return attacks[:2]

    if risk_score < 60:
        return attacks[:3]

    return attacks  # High risk → show all


# ----------------------------------
# Main Simulation Function
# ----------------------------------

def simulate_attack(package_name, risk_score=None):
    """
    Main function to simulate potential attack paths
    """

    category = classify_package(package_name)
    possible_attacks = ATTACK_MAP.get(category, [])

    filtered_attacks = filter_attacks_by_risk(possible_attacks, risk_score)
    impact_level = calculate_impact_level(category, risk_score)

    simulation_result = {
        "package_name": package_name,
        "category": category,
        "impact_level": impact_level,
        "risk_score": risk_score if risk_score else "Not Calculated",
        "simulated_attacks": filtered_attacks,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    return simulation_result


# ----------------------------------
# Optional: Pretty Print (Testing Mode)
# ----------------------------------

if __name__ == "__main__":
    test_package = "cryptography"
    result = simulate_attack(test_package, risk_score=85)

    print("\n=== Attack Simulation Report ===")
    print(f"Package: {result['package_name']}")
    print(f"Category: {result['category']}")
    print(f"Impact Level: {result['impact_level']}")
    print(f"Risk Score: {result['risk_score']}")
    print("Simulated Attacks:")

    for attack in result["simulated_attacks"]:
        print(f"- {attack}")

    print(f"Generated At: {result['timestamp']}")