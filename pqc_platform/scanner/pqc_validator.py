def evaluate_pqc(cipher, tls_version=None):

    if not cipher:
        return "Unknown", 80

    cipher = cipher.upper()

    risk_score = 0

    # TLS Version risk
    if tls_version == "TLSv1.3":
        risk_score += 5
    elif tls_version == "TLSv1.2":
        risk_score += 20
    elif tls_version in ["TLSv1", "TLSv1.1"]:
        risk_score += 40
    else:
        risk_score += 50

    # Encryption algorithm strength
    if "AES_256" in cipher:
        risk_score += 5
    elif "AES_128" in cipher:
        risk_score += 15
    elif "CHACHA20" in cipher:
        risk_score += 5
    else:
        risk_score += 25

    # Classical key exchange
    if "RSA" in cipher:
        risk_score += 35

    if "ECDHE" in cipher:
        risk_score += 15

    # Hash algorithm
    if "SHA384" in cipher:
        risk_score += 3
    elif "SHA256" in cipher:
        risk_score += 5
    else:
        risk_score += 15

    # PQC algorithms
    if "KYBER" in cipher or "DILITHIUM" in cipher:
        return "PQC Ready", 5

    # Classification
    if risk_score <= 25:
        return "Standard", risk_score

    if risk_score <= 55:
        return "Legacy", risk_score

    return "Critical", risk_score
