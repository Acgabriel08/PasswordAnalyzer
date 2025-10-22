# Password Strength Analyzer 🛡️

A Python project that checks password strength and verifies passwords against known breaches using the Have I Been Pwned API. Perfect for cybersecurity students learning password security.

---

## Features

- Detects weak, predictable, or breached passwords
- Scores passwords based on:
  - Length
  - Uppercase & lowercase letters
  - Digits
  - Symbols
- Visual strength bar (0–10)
- Suggestions for improvement
- Optional Have I Been Pwned (HIBP) API check
- Safe logging (masked passwords only)

---

## Installation

1. Open your terminal in this project folder
2. Run:
```
pip install -r requirements.txt
```

---

## Usage

Run the script:

```
python password_strength.py
```

- Enter your password when prompted  
- See the strength score, suggestions, and optional breach check results  

---

## Screenshots

*(Add screenshots in a folder called `screenshots` and reference them here)*

Example:

```
![Password Analyzer Output](screenshots/output.png)
```

---

## License

MIT License (optional)  

---

## Portfolio Notes

This project demonstrates:

- Cybersecurity fundamentals (CIA triad, password security)
- Python scripting, testing, and debugging
- API integration (Have I Been Pwned) and safe handling of sensitive data