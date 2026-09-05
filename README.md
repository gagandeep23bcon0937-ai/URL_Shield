# URL Phishing Detection System 
At the heart of URL Shield is a custom-built, static heuristics analyzer. Instead of relying on simple, outdated blocklists, the algorithm actively scans the structural and semantic components of a URL in real-time to identify phishing indicators.
No CSS or JavaScript files are used.

## Key Security Checks:
-Typosquatting Engine: Utilizes a mathematical sequence-matching algorithm to identify lookalike domains attempting to spoof trusted entities (e.g., detecting "g00gle.com") .
-Obfuscation Detection: Flags URLs hiding behind raw IP addresses, suspicious URL shorteners, or deceptive @ symbol routing.
-Linguistic Analysis: Scans the URL string for high-risk social engineering keywords (e.g., "secure", "verify", "wallet") and excessive subdomains.
-Risk Scoring: Aggregates data from 10 distinct security checks into a cumulative 0-100 threat score, outputting a clear safety verdict alongside an itemized inspection breakdown.

## Project Structure

```text
URL_Shield_Flask_Simple_HTML/
├── app.py
├── phishing_detector.py
├── requirements.txt
├── README.md
└── templates/
    └── index.html
```

## How to Run

```bash
pip install -r requirements.txt
python app.py
```

Open this in your browser:

```text
http://127.0.0.1:5000
```

## JSON API

```text
http://127.0.0.1:5000/analyze?url=https://g00gle.com
```

## Score Meaning

- 0-30: Likely safe
- 31-60: Suspicious
- 61-100: High risk
