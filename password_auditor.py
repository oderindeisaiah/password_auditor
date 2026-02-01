import re
import hashlib

COMMON_PASSWORDS = {
    hashlib.sha256(p.encode()).hexdigest()
    for p in [
        "password",
        "123456",
        "qwerty",
        "admin",
        "iloveyou",
        "welcome",
        "letmein",
        "password123",
    ]
}

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def check_strength(password: str) -> dict:
    score = 0
    issues = []

    if len(password) >= 12:
        score += 2
    else:
        issues.append("Use at least 12 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        issues.append("Add an uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        issues.append("Add a lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        issues.append("Include a number.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        issues.append("Include a special character.")

    breached = hash_password(password) in COMMON_PASSWORDS

    return {
        "score": score,
        "issues": issues,
        "breached": breached,
    }

def main():
    print("=== Password Auditor ===")
    pwd = input("Enter a password to analyze: ").strip()

    result = check_strength(pwd)

    print("\nSecurity Report:")
    print(f"Strength Score: {result['score']} / 6")

    if result["breached"]:
        print("⚠️ ALERT: This password appears in a known breach list (simulated).")

    if result["issues"]:
        print("\nImprovements needed:")
        for issue in result["issues"]:
            print(f"- {issue}")
    else:
        print("\nExcellent password! Strong and safe.")

if __name__ == "__main__":
    main()