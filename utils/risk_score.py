def calculate_risk(attack_type, sector, severity):
    """
    Calculates a simple risk score (0-100) based on attributes.
    """
    score = 0
    
    # Attack Type Weights
    if attack_type == "Ransomware":
        score += 40
    elif attack_type == "DDoS":
        score += 30
    elif attack_type == "Phishing":
        score += 20
    elif attack_type == "Malware":
        score += 25
    else:
        score += 10

    # Sector Weights - keeping this as it adds flavor
    if sector == "Finance":
        score += 30
    elif sector == "Healthcare":
        score += 30
    elif sector == "Government":
        score += 20
    elif sector == "Manufacturing":
        score += 20
    else:
        score += 10

    # Severity Weights (Simulated "Severity" component of the new model)
    if severity == "Critical":
        score += 30
    elif severity == "High":
        score += 25
    elif severity == "Medium":
        score += 15
    elif severity == "Low":
        score += 5
        
    # Volume & Trend Simulation (Randomized or passed in, but here we just add a base factor for now to represent "Analysis")
    # In a real system, this would query historical volume.
    # We will simulate "High Volume" impact if the score is already getting high.
    if score > 60:
        score += 10 # Simulate "High Volume/Trend" boost
        
    return min(score, 100)

def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"
