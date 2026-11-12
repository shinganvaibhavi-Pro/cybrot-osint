# CYBROT OSINT
### Open-Source Intelligence & Cybersecurity Reconnaissance Platform

Cybrot OSINT is a web-based Open-Source Intelligence (OSINT) platform designed to collect, analyze, and present publicly available information about domains and their associated infrastructure.

The platform provides a centralized dashboard for performing domain intelligence gathering, infrastructure analysis, security assessments, and generating PDF reports.

---

## Project Overview

Cybrot OSINT combines a modern web dashboard with a Python-based backend to simplify passive reconnaissance and security information gathering.

It helps security analysts and cybersecurity teams understand publicly accessible information about a target domain through multiple intelligence modules.

**Key objectives:**
- Simplify domain-based OSINT investigations.
- Automate the collection of publicly available intelligence.
- Identify domain and infrastructure-related information.
- Analyze website security configurations.
- Present findings through a centralized dashboard.
- Generate downloadable investigation reports.

## Features

### 1. DNS Analysis
- DNS record lookup.
- Domain resolution information.
- Nameserver and mail server information.

### 2. Domain Intelligence
- Domain-related intelligence gathering.
- Registration and ownership information where available.
- Public domain metadata.

### 3. Subdomain Discovery
- Passive subdomain discovery.
- Certificate Transparency-based hostname discovery where supported.
- Identification of publicly observable subdomains.

### 4. Infrastructure Analysis
- Public IP address identification.
- IP-related information.
- Infrastructure and network intelligence.

### 5. SSL/TLS Analysis
- SSL/TLS certificate inspection.
- Certificate issuer information.
- Certificate validity details.
- Certificate verification status.

### 6. Email Security Analysis
- Email-related DNS configuration checks.
- SPF information.
- DMARC information.
- DKIM information where supported.

### 7. Technology Stack Detection
- Website technology identification.
- Server and framework indicators.
- Publicly observable technology information.

### 8. Security Headers Analysis
- HTTP security header inspection.
- Security configuration observations.
- Identification of missing or weak security headers.

### 9. Threat Intelligence
- Threat intelligence integration.
- External intelligence enrichment where configured.
- API-based intelligence sources where supported.

### 10. Report Generation
- Investigation result compilation.
- PDF report generation.
- Downloadable scan reports.

*Module availability and results depend on the target domain, external data sources, network connectivity, and API configuration.*

---

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | Next.js |
| UI | React, TypeScript, CSS |
| Backend | Python |
| API Framework | FastAPI |
| ASGI Server | Uvicorn |
| Data Storage | SQLite |
| Intelligence Collection | DNS, RDAP and HTTP-based sources |
| Report Export | PDF |

---

## Project Architecture

```text
                  CYBROT OSINT
                       |
          +------------+------------+
          |                         |
      Frontend                   Backend
          |                         |
       Next.js                   FastAPI
          |                         |
     Web Dashboard           OSINT Modules
                                    |
              +---------------------+------------------+
              |          |          |         |         |
             DNS      Domain    Subdomain  SSL/TLS  Infrastructure
                       Intel
              |
       Additional Modules
              |
       +------+-------+--------+----------+
       |              |        |          |
     Email          Security  Technology Threat
    Security        Headers    Stack    Intelligence
              |
        Result Processing
              |
        Report Generation
              |
            PDF
```

---

## Repository Structure

```text
cybrot-osint/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   └── modules/
│   │       ├── dns_analysis.py
│   │       ├── domain_intelligence.py
│   │       ├── subdomain_discovery.py
│   │       ├── infrastructure.py
│   │       ├── ssl_analysis.py
│   │       ├── email_security.py
│   │       ├── technology_stack.py
│   │       ├── security_headers.py
│   │       └── threat_intelligence.py
│   │
│   ├── requirements.txt
│   └── database/
│
├── frontend/
│   ├── src/
│   │   └── app/
│   │       ├── page.tsx
│   │       ├── layout.tsx
│   │       └── globals.css
│   └── package.json
│
├── browser-extension/
├── security-qa/
├── tests/
├── docs/
├── research/
│
└── README.md
```

---

## Requirements

Before installing Cybrot OSINT, make sure you have:

- Python 3.11 or compatible version.
- Node.js and npm.
- Git.
- Internet connectivity.
- macOS or Linux environment.

---

## Installation and Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/shinganvaibhavi-Pro/cybrot-osint.git

cd cybrot-osint
```

### Step 2: Configure the Backend

```bash
cd backend

python3 -m venv .venv
```

Activate the virtual environment.

**macOS / Kali Linux:**

```bash
source .venv/bin/activate
```

Install backend dependencies:

```bash
python -m pip install -r requirements.txt
```

### Step 3: Configure SSL Certificates (macOS)

If Python cannot locate trusted SSL certificates, install Certifi:

```bash
./.venv/bin/python -m pip install certifi
```

Configure the certificate bundle in the current Terminal session:

```bash
export SSL_CERT_FILE="$(./.venv/bin/python -c 'import certifi; print(certifi.where())')"

export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"
```

These environment variables need to be set again in a new Terminal session unless configured permanently.

### Step 4: Start the Backend

From the `backend` directory:

```bash
./.venv/bin/python -m uvicorn app.main:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### Step 5: Configure the Frontend

Open a second Terminal window:

```bash
cd ~/cybrot-osint/frontend
```

Install frontend dependencies:

```bash
npm install
```

### Step 6: Start the Frontend

```bash
npm run dev
```

Open the application:

```text
http://localhost:3000
```

---

## Running the Application

Cybrot OSINT requires both the backend and frontend services to run simultaneously.

| Service | Local URL |
|---|---|
| Frontend Dashboard | http://localhost:3000 |
| Backend API | http://127.0.0.1:8000 |
| API Documentation | http://127.0.0.1:8000/docs |

To stop a running service, press:

```text
CTRL + C
```

---

## How to Use

1. Start the backend and frontend services.
2. Open the Cybrot OSINT dashboard.
3. Enter the domain you are authorized to investigate.
4. Initiate the scan.
5. Allow the available intelligence modules to process the target.
6. Review the results displayed in the dashboard.
7. Examine successful, failed, and unconfigured modules.
8. Generate and download the PDF report if report export is available.

---

## API Configuration

Some external intelligence providers may require API credentials.

Configure credentials using environment variables or a local environment configuration file according to the relevant module's implementation.

**Important:**
- Never commit API keys, access tokens, passwords, or private credentials to GitHub.
- Keep local `.env` files out of version control.
- Configure production credentials securely through the hosting provider's environment settings.

---

## Deployment

Cybrot OSINT can be prepared for public deployment using separate hosting services for its frontend and backend.

Suggested deployment architecture:

| Component | Suggested Platform |
|---|---|
| Frontend | Vercel |
| Backend | Render |
| Source Code | GitHub |

Deployment requires correct API URL configuration, CORS settings, secure environment variables, and persistent storage where needed.

Public deployment should only be considered production-ready after testing all modules and report generation.

---

## Security and Responsible Usage

Cybrot OSINT is intended for legitimate cybersecurity research, defensive security analysis, and authorized OSINT investigations.

Users must:

- Investigate only domains and infrastructure they own or have permission to assess.
- Respect applicable laws, regulations, and third-party service terms.
- Avoid using collected intelligence for unauthorized access or malicious activities.
- Protect API credentials and investigation data.
- Verify findings before making security decisions.

The accuracy and availability of results may depend on external services, network restrictions, target configurations, and API access.

---

## Project Status

**Development Status:** Active Development

Cybrot OSINT is under development. Individual modules may have different levels of functionality depending on the operating system, dependencies, external services, and configuration.

Testing and improvements are ongoing.

---

## Future Enhancements

Potential areas of improvement include:

- Enhanced domain intelligence collection.
- Improved subdomain discovery.
- Additional threat intelligence integrations.
- Better scan history and investigation management.
- Improved PDF reporting and export functionality.
- Cross-platform compatibility improvements.
- Enhanced error handling and module status reporting.
- Production deployment and performance optimization.

---

## Contributing

Contributions, suggestions, and improvements are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Test the changes locally.
5. Submit a pull request with a clear description.

---

## Repository

**GitHub:** https://github.com/shinganvaibhavi-Pro/cybrot-osint

---

## Disclaimer

Cybrot OSINT is developed for educational, research, and authorized cybersecurity purposes. The developers are not responsible for misuse of this software or any unauthorized investigation conducted using it.

---

**CYBROT OSINT — Discover. Analyze. Secure.***
