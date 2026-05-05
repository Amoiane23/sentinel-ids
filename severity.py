def map_severity(label):
    label = str(label).strip().upper()

    critical_labels = {"DDOS", "DOS", "RANSOMWARE"}
    high_labels = {"PORTSCAN", "BOTNET", "BRUTEFORCE", "SSH BRUTE FORCE"}
    medium_labels = {"WEB ATTACK - XSS", "XSS", "SQL INJECTION", "WEB ATTACK"}
    low_labels = {"BENIGN", "NORMAL", "SAFE"}

    if label in critical_labels:
        return "CRITICAL"
    elif label in high_labels:
        return "HIGH"
    elif label in medium_labels:
        return "MEDIUM"
    elif label in low_labels:
        return "INFO"
    else:
        return "LOW"