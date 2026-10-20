"""
CODTECH Cybersecurity Internship
Project 2: Password Strength Checker

Features:
- Checks password length and character variety.
- Detects common password weaknesses.
- Provides a strength rating.
- Suggests improvements.
- Does not store or transmit passwords.
"""

import re
import tkinter as tk
from tkinter import ttk


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
    "111111",
}


def check_password(password):
    """Evaluate a password and return its rating and suggestions."""

    score = 0
    suggestions = []

    if not password:
        return "Not evaluated", 0, ["Enter a password to begin."]

    # Check common passwords
    if password.lower() in COMMON_PASSWORDS:
        return (
            "Very Weak",
            0,
            [
                "This is a commonly used password.",
                "Choose a unique password or passphrase.",
            ],
        )

    # Length
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("Prefer 12 or more characters.")

    # Character variety
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Consider including lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Consider including uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Consider including numbers.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Consider including symbols.")

    # Detect repeated characters
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        suggestions.append("Avoid repeating the same character many times.")

    # Detect simple sequences
    lower_password = password.lower()

    simple_sequences = [
        "1234",
        "2345",
        "3456",
        "4567",
        "5678",
        "6789",
        "abcd",
        "bcde",
        "cdef",
        "qwerty",
        "asdf",
    ]

    if any(sequence in lower_password for sequence in simple_sequences):
        score -= 1
        suggestions.append("Avoid predictable keyboard or character sequences.")

    # Determine rating
    score = max(0, min(score, 6))

    if len(password) < 8 or score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"

    if strength == "Strong":
        suggestions.insert(
            0,
            "Good result! Keep using unique passwords for different accounts.",
        )

    if not suggestions:
        suggestions.append("No basic weaknesses detected by these checks.")

    return strength, score, suggestions


def evaluate_password():
    """Read the input and display the result."""

    password = password_entry.get()

    strength, score, suggestions = check_password(password)

    strength_label.config(text=f"Strength: {strength}")
    score_label.config(text=f"Checks passed: {score}/6")

    suggestions_text.config(state="normal")
    suggestions_text.delete("1.0", tk.END)

    for suggestion in suggestions:
        suggestions_text.insert(tk.END, f"• {suggestion}\n")

    suggestions_text.config(state="disabled")


def toggle_password_visibility():
    """Show or hide the entered password."""

    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")


def clear_fields():
    """Clear the input and displayed results."""

    password_entry.delete(0, tk.END)
    strength_label.config(text="Strength: Not evaluated")
    score_label.config(text="Checks passed: 0/6")

    suggestions_text.config(state="normal")
    suggestions_text.delete("1.0", tk.END)
    suggestions_text.insert(
        tk.END,
        "Enter a password and click Check Strength.",
    )
    suggestions_text.config(state="disabled")


# Create application window
root = tk.Tk()
root.title("CODTECH Password Strength Checker")
root.geometry("540x450")
root.resizable(False, False)

# Main container
main_frame = ttk.Frame(root, padding=20)
main_frame.pack(fill="both", expand=True)

# Heading
title_label = ttk.Label(
    main_frame,
    text="Password Strength Checker",
    font=("Arial", 18, "bold"),
)
title_label.pack(pady=(0, 8))

subtitle_label = ttk.Label(
    main_frame,
    text="Check password characteristics and get improvement tips.",
    wraplength=480,
)
subtitle_label.pack(pady=(0, 18))

# Password input
ttk.Label(
    main_frame,
    text="Enter a password to evaluate:",
).pack(anchor="w")

password_entry = ttk.Entry(
    main_frame,
    width=55,
    show="*",
)
password_entry.pack(fill="x", pady=8)

# Visibility checkbox
show_password_var = tk.BooleanVar(value=False)

ttk.Checkbutton(
    main_frame,
    text="Show password",
    variable=show_password_var,
    command=toggle_password_visibility,
).pack(anchor="w", pady=(0, 12))

# Buttons
button_frame = ttk.Frame(main_frame)
button_frame.pack(pady=5)

ttk.Button(
    button_frame,
    text="Check Strength",
    command=evaluate_password,
).grid(row=0, column=0, padx=5)

ttk.Button(
    button_frame,
    text="Clear",
    command=clear_fields,
).grid(row=0, column=1, padx=5)

# Results
strength_label = ttk.Label(
    main_frame,
    text="Strength: Not evaluated",
    font=("Arial", 12, "bold"),
)
strength_label.pack(pady=(15, 5))

score_label = ttk.Label(
    main_frame,
    text="Checks passed: 0/6",
)
score_label.pack(pady=3)

ttk.Label(
    main_frame,
    text="Suggestions:",
    font=("Arial", 10, "bold"),
).pack(anchor="w", pady=(12, 3))

suggestions_text = tk.Text(
    main_frame,
    height=5,
    width=60,
    wrap="word",
)
suggestions_text.pack(fill="both", expand=True)

suggestions_text.insert(
    tk.END,
    "Enter a password and click Check Strength.",
)
suggestions_text.config(state="disabled")

# Footer
ttk.Label(
    main_frame,
    text="Analysis runs locally. Passwords are not saved.",
    font=("Arial", 8),
).pack(pady=(8, 0))

root.mainloop()
