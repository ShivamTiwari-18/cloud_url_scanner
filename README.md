# Cloud Bucket Scanner 🔍

A Python CLI tool to scan cloud storage URLs (S3, Azure Blob, GCP) for **public access, misconfigurations, and indexing**. It helps detect risks and generate clear reports.

---

## Features
- Scan cloud bucket URLs for open access
- Detect read/write permissions
- Check for exposed directory indexing
- Generate JSON/HTML/CSV risk reports
- Optional AWS SDK integration

---

## Installation
```bash
git clone https://github.com/<your-username>/cloud-bucket-scanner.git
cd cloud-bucket-scanner
pip install -r requirements.txt

Usage

Single URL:

python scanner.py --url https://example-bucket.s3.amazonaws.com


Multiple URLs:

python scanner.py --input urls.txt --output report.json




Example Report (JSON)
{
  "url": "https://example-bucket.s3.amazonaws.com",
  "provider": "aws-s3",
  "read_access": true,
  "write_access": false,
  "indexed": true,
  "risk_level": "High"
}

Risk Levels

High: Public write access or sensitive files

Medium: Public read + index listing

Low: Limited/no public access

