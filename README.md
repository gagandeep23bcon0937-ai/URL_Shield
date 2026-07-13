# URL Shield - Flask Simple HTML Version

This is a simple Flask + Python phishing URL analyzer.

It includes:

- A plain HTML form to enter a URL
- A Check URL button
- A risk score output from 0 to 100
- A safety verdict
- A detailed check table
- A JSON API route for testing

No CSS or JavaScript files are used.

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
