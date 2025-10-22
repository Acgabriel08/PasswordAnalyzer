# Password Strength Analyzer

A Python tool to check password strength with advanced checks:

- Common password / leetspeak detection  
- Visual strength scoring (0–10)  
- Suggestions for improvement  
- Optional **Have I Been Pwned** breach check (k-anonymity API)  
- Safe logging (masked passwords only)  

---

## Features

- Detects weak, predictable, or breached passwords  
- Scores passwords on length, uppercase/lowercase letters, digits, and symbols  
- Visual strength bar and suggestions  
- Logs anonymized results for auditing  

---

## Usage

1. Install dependencies:

```bash
pip install -r requirements.txt