# Final Audit

## Verification status

Passed on May 2, 2026.

## Commands executed

```bash
python -m pip install -e .[dev]
npm install
python tools/generate_sample_reports.py
python -m pytest tests -q
npm run lint:web
npm run build:web
npm run audit
python C:\Users\samee\.codex\skills\webapp-testing\scripts\with_server.py --server "npm run preview:web" --port 5192 --timeout 90 -- python tests\browser_smoke.py
```

## Outcomes

- `pytest`: `3/3` passing
- sample report generation: passing
- web lint: passing
- production web build: passing
- browser smoke: passing

## Verified artifacts

- generated JSON:
  - `apps/web/public/vulnerable-report.json`
  - `apps/web/public/secure-report.json`
- generated HTML:
  - `results/vulnerable-report.html`
  - `results/secure-report.html`
- screenshots:
  - `docs/screenshots/dashboard.png`
  - `docs/screenshots/findings.png`

## Audit notes

- Fixed a GitHub Actions YAML parsing issue where PyYAML treated the `on:` key as a boolean-like token, which would have hidden trigger-based findings.
- Refined permission scoring to avoid false positives for `security-events: write` in CodeQL workflows.
- Confirmed the vulnerable fixture resolves to a `100/100` risk score and the hardened fixture resolves to `0/100`.
