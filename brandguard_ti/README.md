
# BrandGuard Threat Intel Demo

A passive phishing and trademark-abuse analyzer with a visual dashboard.

## What it does
- Captures a page in a headless browser
- Checks for login/phishing cues
- Compares the page against an optional brand name, official domain, and logo
- Enriches the result using free public sources:
  - URLhaus public text feed
  - Certificate Transparency lookup via crt.sh
  - IP/ASN details via RDAP / IPWhois
- Produces analyst-style action items

## Run locally
```bash
pip install -r requirements.txt
playwright install chromium
uvicorn app:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000

## Demo flow
1. Paste a suspicious URL
2. Optionally enter the brand name and official domain
3. Upload the official logo if you want logo matching
4. Review the score ring, category bars, threat-intel panel, and action plan

## Extending later
- Add a `brands.json` file for 50+ brand profiles
- Add OCR and stronger logo embeddings
- Add more public feeds
- Add a storage layer for historical incidents and model improvement
