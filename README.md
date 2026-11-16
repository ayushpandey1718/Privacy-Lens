# PrivacyLens — VS Code recreation

A dark, responsive recreation of the supplied PrivacyLens screenshots, with an interactive Next.js frontend and a FastAPI backend.

## Requirements
- Node.js 20+
- Python 3.10+
- VS Code

## 1. Start the backend (Terminal 1)
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
API health: http://127.0.0.1:8000/api/health

## 2. Start the frontend (Terminal 2)
```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```
Open http://localhost:3000

## Features
- Overview dashboard with sample metrics, risk distribution, recent scans and latest findings.
- Findings search and severity/category filters.
- Illustrative data-flow explorer.
- SDK inventory.
- Privacy policy review with review-state toggles.
- Reports table and JSON/CSV export.
- Settings with local preferences.
- New scan form with APK/ZIP selection and configurable checks.
- FastAPI upload endpoint. The backend safely inspects archive metadata and text/XML evidence; binary Android manifests require the optional Androguard package for deeper parsing.

## Important evidence limitation
Sample records are illustrative. Static analysis can identify declared permissions and possible code paths; it does not prove runtime access, transmission, or actual data collection. Findings are signals for human review, not legal or security certification.

## Notes
This is an original implementation based on the screenshots you supplied, not a copy of the original site's source code. The sample dashboard figures are demonstration data. Uploaded APKs are processed locally by the API in this starter; add authentication, file-size limits at the reverse proxy, malware scanning, retention controls, and isolated analysis before deploying publicly.
