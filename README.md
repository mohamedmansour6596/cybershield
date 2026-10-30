# CyberShield

Educational phishing-link analyser. Links are analysed as text only; the server never visits them.

## Run locally
```
pip install -r requirements.txt
flask --app app run
```
Open http://127.0.0.1:5000

## Structure
```
CyberShield/
├── app.py
├── requirements.txt
├── templates/  (base, index, scanner, dashboard, guide, error)
└── static/     (style.css, script.js)
```

## Security
SSRF-safe static analysis, CSRF tokens, rate limiting (10/min/IP), input validation,
output escaping, parameterised SQL, CSP and other security headers.
