#!/usr/bin/env python3
"""
Password Strength Analyzer & Generator
Categorizes passwords into Weak, Medium, or Strong based on length, character diversity, and entropy.
"""

import math
import re
import string
import random
import sys


def calculate_entropy(password: str) -> float:
    """Calculates password entropy in bits."""
    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'[0-9]', password):
        pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool_size += 32  # standard punctuation/symbols count

    if pool_size == 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 1)


def evaluate_password(password: str) -> dict:
    """
    Evaluates password strength across multiple criteria.
    Returns detailed metrics, classification (Weak/Medium/Strong), and recommendations.
    """
    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    types_count = sum([has_lower, has_upper, has_digit, has_symbol])
    entropy = calculate_entropy(password)

    # Common weak password patterns check
    common_weak = ['password', '123456', '12345678', 'qwerty', 'admin', 'welcome', 'letmein', 'monkey', '111111']
    is_common = password.lower() in common_weak

    # Criteria breakdown
    criteria = {
        "length_8": length >= 8,
        "length_12": length >= 12,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
    }

    # Score calculation (0 - 100)
    score = 0

    # Length scoring (up to 40 points)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 10
    else:
        score += 5

    # Diversity scoring (up to 40 points, 10 per category)
    score += types_count * 10

    # Bonus points for combination & length (up to 20 points)
    if length >= 10 and types_count >= 3:
        score += 10
    if length >= 12 and types_count == 4:
        score += 10

    # Penalties
    if is_common:
        score = min(score, 15)
    elif length < 6:
        score = min(score, 25)

    # Determine strength label
    if is_common or length < 8 or score < 45 or types_count < 2:
        strength = "Weak"
        color = "\033[91m"  # Red
        badge = "[ WEAK ]"
    elif score < 75 or types_count < 3 or length < 10:
        strength = "Medium"
        color = "\033[93m"  # Yellow
        badge = "[ MEDIUM ]"
    else:
        strength = "Strong"
        color = "\033[92m"  # Green
        badge = "[ STRONG ]"

    RESET = "\033[0m"

    # Feedback / Recommendations
    suggestions = []
    if length < 8:
        suggestions.append("Increase password length to at least 8 characters (12+ recommended).")
    elif length < 12:
        suggestions.append("Make it 12 characters or longer for extra security.")

    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z).")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z).")
    if not has_digit:
        suggestions.append("Add numeric digits (0-9).")
    if not has_symbol:
        suggestions.append("Add special symbols (!@#$%^&*...).")

    if is_common:
        suggestions.append("CRITICAL: Avoid using common words or predictable patterns!")

    return {
        "password": password,
        "length": length,
        "score": score,
        "strength": strength,
        "badge": badge,
        "color": color,
        "reset": RESET,
        "entropy": entropy,
        "criteria": criteria,
        "suggestions": suggestions,
        "is_common": is_common
    }


def generate_strong_password(length: int = 16) -> str:
    """Generates a secure random password with guaranteed character diversity."""
    if length < 12:
        length = 12

    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Ensure at least one character from each set
    password_chars = [
        random.choice(lowers),
        random.choice(uppers),
        random.choice(digits),
        random.choice(symbols)
    ]

    all_chars = lowers + uppers + digits + symbols
    for _ in range(length - 4):
        password_chars.append(random.choice(all_chars))

    random.shuffle(password_chars)
    return "".join(password_chars)


def print_result(res: dict):
    """Prints a beautiful colored breakdown of the password strength."""
    c = res["color"]
    r = res["reset"]
    
    print("\n" + "=" * 55)
    print(f"  PASSWORD STRENGTH ASSESSMENT: {c}{res['badge']}{r}")
    print("=" * 55)
    print(f"  Password Analyzed : {'*' * res['length']} (Length: {res['length']})")
    print(f"  Overall Score     : {res['score']} / 100")
    print(f"  Estimated Entropy : {res['entropy']} bits")
    print("-" * 55)
    print("  CRITERIA CHECKLIST:")
    
    def check_mark(val):
        return "\033[92m[✓]\033[0m" if val else "\033[91m[✗]\033[0m"

    crit = res["criteria"]
    print(f"   {check_mark(crit['length_8'])} Length >= 8 characters")
    print(f"   {check_mark(crit['length_12'])} Length >= 12 characters (Recommended)")
    print(f"   {check_mark(crit['has_upper'])} Contains Uppercase Letters (A-Z)")
    print(f"   {check_mark(crit['has_lower'])} Contains Lowercase Letters (a-z)")
    print(f"   {check_mark(crit['has_digit'])} Contains Numeric Digits (0-9)")
    print(f"   {check_mark(crit['has_symbol'])} Contains Special Symbols (!@#$...)")
    
    if res["suggestions"]:
        print("-" * 55)
        print("  RECOMMENDATIONS TO IMPROVE STRENGTH:")
        for s in res["suggestions"]:
            print(f"   • {s}")
    else:
        print("-" * 55)
        print("  \033[92m★ Outstanding! Your password meets high security standards.\033[0m")
    
    print("=" * 55 + "\n")


def main():
    print("\n" + "🔒" + "  PASSWORD STRENGTH CHECKER & ANALYZER  " + "🔒")
    print("--------------------------------------------------")
    
    while True:
        print("\nOptions:")
        print("  1. Test a password")
        print("  2. Generate a strong password")
        print("  3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == "1":
            pwd = input("Enter password to test: ")
            if not pwd:
                print("\n\033[91mError: Password cannot be empty.\033[0m")
                continue
            res = evaluate_password(pwd)
            print_result(res)
            
        elif choice == "2":
            try:
                length_str = input("Enter desired length (default 16): ").strip()
                length = int(length_str) if length_str else 16
            except ValueError:
                length = 16
            
            gen_pwd = generate_strong_password(length)
            print(f"\n🔑 Generated Strong Password: \033[96m{gen_pwd}\033[0m")
            res = evaluate_password(gen_pwd)
            print_result(res)
            
        elif choice == "3":
            print("\nThank you for using Password Strength Checker. Stay secure!\n")
            sys.exit(0)
        else:
            print("\033[91mInvalid choice. Please select 1, 2, or 3.\033[0m")


if __name__ == "__main__":
    main()
