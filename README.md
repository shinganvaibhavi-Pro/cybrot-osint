
## About the Project

CYBROT OSINT is a local-first website intelligence and OSINT automation platform. It is designed to collect and organize publicly available information about websites and domains.

The project aims to provide a dashboard and browser extension connected to a local Python engine.

## Key Features

- Domain and RDAP information collection
- DNS record analysis
- Passive subdomain discovery
- TLS/SSL certificate inspection
- Website technology fingerprinting
- Website metadata collection
- Security headers analysis
- Email security checks
- Local database storage
- OSINT results dashboard

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Database | SQLite |
| Frontend | Next.js, TypeScript |
| Browser Extension | Chrome and Microsoft Edge |
| Operating System | Kali Linux, Windows, macOS |

## Project Structure

```text
cybrot-osint/
├── backend/
│   ├── engine/
│   ├── collectors/
│   ├── api/
│   └── database/
├── frontend/
├── browser-extension/
├── research/
├── security-qa/
├── tests/
└── docs/
```

## Team Responsibilities

- **Team A – Python Backend:** Develop the core engine and APIs.
- **Team B – OSINT Research:** Research public OSINT sources and collection methods.
- **Team C – Frontend Dashboard:** Develop the web dashboard.
- **Team D – Browser Extension:** Build Chrome and Edge extensions.
- **Team E – Security and QA:** Test security, validate inputs, and perform regression testing.

## Security Principles

- Passive collection by default.
- Local API should bind to `127.0.0.1`.
- Validate user inputs.
- Implement SSRF protections.
- Use authentication for local API requests.
- Do not commit API keys, passwords, or tokens.
- Do not perform scans without user consent.

## Project Status

**Status:** Initial repository structure created. Development and research are in progress.

## Disclaimer

This project is intended for authorized security research, defensive security analysis, and educational purposes. Only investigate websites and domains you are authorized to assess.

# cybrot-osint
Local-first Website Intelligence and OSINT Automation Platform 
