# password_strength.py
# Password Strength Analyzer with:
#  - common/leet detection
#  - scoring 0-10 with visual bar
#  - optional Have I Been Pwned (HIBP) k-anonymity check (network)
#  - safe logging (masked only)
#
# Requirements: pip install requests

import re
import hashlib
import requests
from datetime import datetime, timezone

# -----------------------------
# Configuration
# -----------------------------
HIBP_RANGE_API = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "PasswordAnalyzer/1.0 (your-email@example.com)"
LOG_ENABLED = True
LOG_FILE = "password_analyzer_log.txt"  # Add to .gitignore before committing

# -----------------------------
# Common password & leet rules
# -----------------------------
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "password1", "111111", "123456789", "12345", "1234"
}

BANNED_SUBSTRINGS = {"password", "pass", "admin", "qwerty", "letmein", "welcome"}

LEET_MAP = str.maketrans({
    "@": "a",
    "0": "o",
    "1": "l",
    "3": "e",
    "$": "s",
    "5": "s",
    "7": "t",
    "4": "a",
    "!": "i"
})

# -----------------------------
# Utility functions
# -----------------------------
def mask_password_for_log(pw):
    if not pw:
        return ""
    if len(pw) <= 2:
        return pw[0] + "*" * (len(pw)-1)
    return pw[0] + "*" * (len(pw)-2) + pw[-1]

def normalise_leet(pw):
    translated = pw.translate(LEET_MAP)
    alpha_core = re.sub(r"[^a-zA-Z]", "", translated).lower()
    return alpha_core

def is_obvious_sequence(pw):
    if re.search(r"\d{3,}", pw):
        return True
    if re.search(r"(.)\1\1", pw):
        return True
    sequences = ["1234", "2345", "3456", "4567", "5678", "6789", "7890",
                 "qwer", "asdf", "zxcv", "abcd", "password"]
    low = pw.lower()
    for s in sequences:
        if s in low:
            return True
    return False

def is_common_variant(password):
    pw_lower = password.lower().strip()
    if pw_lower in COMMON_PASSWORDS:
        return True
    core = normalise_leet(password)
    if core and core in COMMON_PASSWORDS:
        return True
    for sub in BANNED_SUBSTRINGS:
        if sub in core:
            return True
    if is_obvious_sequence(password):
        return True
    return False

# -----------------------------
# HIBP k-anonymity check
# -----------------------------
def check_pwned(password, user_agent=USER_AGENT):
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        headers = {"User-Agent": user_agent}
        resp = requests.get(HIBP_RANGE_API + prefix, headers=headers, timeout=10)
        if resp.status_code != 200:
            return None
        for line in resp.text.splitlines():
            parts = line.split(':')
            if len(parts) != 2:
                continue
            returned_suffix, count = parts[0].strip(), parts[1].strip()
            if returned_suffix.upper() == suffix:
                try:
                    return int(count)
                except ValueError:
                    return 1
        return 0
    except requests.RequestException:
        return None

# -----------------------------
# Safe logging
# -----------------------------
def log_result(masked_pw, score, strength_label, pwned_count):
    timestamp = datetime.now(timezone.utc).isoformat()  # timezone-aware UTC
    pwned_str = "unknown" if pwned_count is None else str(pwned_count)
    line = f"{timestamp}\t{masked_pw}\t{score}/10\t{strength_label}\tpwned:{pwned_str}\n"
    if LOG_ENABLED:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

# -----------------------------
# Main scoring function
# -----------------------------
def check_strength(password, use_hibp=True):
    if not password:
        print("No password entered.")
        return

    # 1) common-variant check
    if is_common_variant(password):
        strength_label = "❌ Very Weak (common or predictable pattern detected)"
        score = 0
        bar = "[----------]"
        print(f"\nPassword Strength: {strength_label}")
        print(f"Score: {score} / 10")
        print(bar)
        print("Suggestions:\n - Avoid common words or predictable patterns.\n - Use a unique long passphrase.")
        log_result(mask_password_for_log(password), score, strength_label, 0)
        return

    # 2) optional HIBP check
    pwned_count = None
    if use_hibp:
        pwned_count = check_pwned(password)
        if pwned_count is None:
            print("Warning: Could not check password against breach database. Continuing local checks...")
        elif pwned_count > 0:
            strength_label = "❌ Very Weak (found in data breaches)"
            score = 0
            bar = "[----------]"
            print(f"\nPassword Strength: {strength_label}")
            print(f"Seen {pwned_count} times in breaches.")
            print(f"Score: {score} / 10")
            print(bar)
            print("Suggestions:\n - Do not reuse breached passwords. Use a unique passphrase or a manager.")
            log_result(mask_password_for_log(password), score, strength_label, pwned_count)
            return

    # 3) scoring rules
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password too short (minimum 8 characters).")

    if re.search(r"[A-Z]", password):
        score += 2
    else:
        feedback.append("❌ Add at least one uppercase letter (A-Z).")

    if re.search(r"[a-z]", password):
        score += 2
    else:
        feedback.append("❌ Add at least one lowercase letter (a-z).")

    if re.search(r"[0-9]", password):
        score += 2
    else:
        feedback.append("❌ Add at least one number (0-9).")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>~`+=_\-]", password):
        score += 2
    else:
        feedback.append("❌ Add at least one special character (!,@,#,$, etc).")

    if score % 2 == 1:
        score += 1

    if score >= 9:
        strength_label = "✅ Strong"
    elif score >= 6:
        strength_label = "⚠️ Moderate"
    else:
        strength_label = "❌ Weak"

    filled_slots = score // 2
    total_slots = 5
    bar = "[" + "#" * filled_slots + "-" * (total_slots - filled_slots) + "]"

    print(f"\nPassword Strength: {strength_label}")
    print(f"Score: {score} / 10")
    print(bar)
    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(" -", tip)
    else:
        print("Great! Your password meets the basic recommended checks.")

    log_result(mask_password_for_log(password), score, strength_label, pwned_count)

# -----------------------------
# Run the script
# -----------------------------
if __name__ == "__main__":
    user_input = input("Enter your password to test: ")
    check_strength(user_input, use_hibp=True)