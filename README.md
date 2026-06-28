# Threat Intelligence Aggregator (Non-AI)

## Overview

The **Threat Intelligence Aggregator (Non-AI)** is a Python-based cybersecurity toolkit developed as part of the **Unified Mentor Cybersecurity Internship**.

The project collects, validates, normalizes, correlates, and reports **Indicators of Compromise (IOCs)** from multiple threat intelligence sources without using Artificial Intelligence or Machine Learning.

It demonstrates practical **Blue Team** techniques used in Security Operations Centers (SOC), including IOC parsing, threat feed aggregation, correlation analysis, blocklist generation, and reporting.

---

# Features

## IOC Feed Collection

Supports loading threat intelligence from:

* Local TXT files
* CSV files
* JSON IOC feeds
* STIX Bundle (JSON)
* Remote URL-based threat feeds

Users can:

* Use existing feeds
* Upload one or multiple custom feeds
* Download public OSINT threat feeds

---

## Supported IOC Types

* IPv4 Addresses
* Domains
* URLs
* Email Addresses
* MD5 Hashes
* SHA-256 Hashes

---

## Feed Validation

Before processing, every uploaded feed is validated.

Validation includes:

* Supported file type verification
* Empty file detection
* JSON structure validation
* STIX bundle validation
* CSV column validation
* URL validation
* IOC format validation

---

## IOC Normalization

Every IOC is normalized into a common format.

Each record contains:

* Indicator
* IOC Type
* Source Feed
* Timestamp
* Category
* Severity

---

## IOC Correlation Engine

The correlation engine identifies repeated indicators appearing across multiple feeds.

Severity Levels:

| IOC Count | Severity |
| --------- | -------- |
| 1         | Low      |
| 2–3       | Medium   |
| 4+        | High     |

---

## SQLite Database

All normalized IOCs are stored in a SQLite database.

Database features include:

* Automatic table creation
* IOC persistence
* Database cleanup before processing
* IOC counting

Database File:

```text
database/threatintel.db
```

---

## Blocklist Generation

Automatically generates:

* IP Blocklist
* Domain Blocklist
* URL Blocklist
* Hash Blocklist
* Email Blocklist

Export Formats:

* TXT
* CSV
* JSON

---

## Reporting

Generates:

* Normalized IOC Database (JSON)
* Correlation Report (CSV)
* PDF Threat Intelligence Report

---

# Project Structure

```text
Threat-Intelligence-Aggregator/
│
├── feeds/
│   ├── domains.txt
│   ├── emails.txt
│   ├── malicious_ips.csv
│   ├── hashes.csv
│   ├── urls.json
│   ├── stix.json
│   ├── feed_urls.txt
│   ├── uploaded/
│   └── downloaded/
│
├── database/
│   └── threatintel.db
│
├── output/
│   ├── normalized_iocs.json
│   ├── correlation_report.csv
│   ├── ip_blocklist.txt
│   ├── domain_blocklist.txt
│   ├── url_blocklist.txt
│   ├── hash_blocklist.txt
│   ├── email_blocklist.txt
│   ├── blocklists.json
│   ├── blocklists.csv
│   └── final_report.pdf
│
├── modules/
├── cli/
├── gui/
├── main.py
├── requirements.txt
└── README.md
```

---

# Workflow

```text
                +-----------------------+
                | Threat Intelligence   |
                | Feed Sources          |
                +-----------+-----------+
                            |
                            v
                  +------------------+
                  | Feed Loader      |
                  +------------------+
                            |
                            v
                  +------------------+
                  | IOC Parser       |
                  +------------------+
                            |
                            v
                  +------------------+
                  | IOC Validator    |
                  +------------------+
                            |
                            v
                  +------------------+
                  | Normalizer       |
                  +------------------+
                            |
                            v
                  +------------------+
                  | SQLite Database  |
                  +------------------+
                            |
                            v
                  +------------------+
                  | Correlation      |
                  +------------------+
                     |            |
                     |            |
                     v            v
             +------------+   +------------+
             | Blocklists |   | PDF Report |
             +------------+   +------------+
```

---

# Technologies Used

## Programming Language

* Python 3.x

## Python Libraries

* os
* csv
* json
* re
* requests
* sqlite3
* ipaddress
* hashlib
* reportlab
* tkinter
* shutil

---

# Installation

Clone the repository:

```bash
git clone <repository-url>
```

Navigate to the project:

```bash
cd Threat-Intelligence-Aggregator
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
py main.py
```

---

# Running the Project

After launching:

```text
1. Command Line Mode
2. GUI Mode
3. Exit
```

Both CLI and GUI support:

* Using existing feeds
* Uploading custom feed(s)
* Processing remote URL feeds
* Generating reports and blocklists

---

# Generated Outputs

After execution, the following files are generated inside the **output/** directory:

* normalized_iocs.json
* correlation_report.csv
* ip_blocklist.txt
* domain_blocklist.txt
* url_blocklist.txt
* hash_blocklist.txt
* email_blocklist.txt
* blocklists.json
* blocklists.csv
* final_report.pdf

---

# Learning Outcomes

This project demonstrates:

* Threat Intelligence aggregation
* IOC parsing and validation
* IOC normalization
* Cross-feed IOC correlation
* Threat prioritization
* SQLite integration
* Blocklist generation
* Threat reporting
* SOC automation concepts

---

# Future Enhancements

Possible future improvements include:

* TAXII 2.1 client support
* VirusTotal API integration
* AbuseIPDB integration
* Scheduled automatic feed updates
* IOC enrichment
* IOC search interface
* Interactive dashboards
* Threat intelligence REST API

---

# Author

**Aman Shaikh**

Cybersecurity Internship Project

Unified Mentor

---

# License

This project is intended for educational and internship purposes.
