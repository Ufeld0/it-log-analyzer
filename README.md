# IT Log Analyzer

AI-powered Windows log analysis tool for IT Security teams.

Parses system logs, identifies critical events, detects brute force attacks, and generates security analysis using Claude AI (Anthropic).

## Features

- Parses structured Windows log files
- Filters WARNING, ERROR, and CRITICAL events
- Detects brute force login attempts (configurable threshold and time window)
- Generates AI security analysis with actionable recommendations
- Outputs formatted report to file

## Requirements

- Python 3.8+
- Anthropic API key

## Installation

```bash
pip install anthropic
```

## Usage

```bash
python log_analyzer.py --input logs.txt --output report.txt
```

## Environment

Set your API key before running:

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

## Example Output
2026-05-25 08:15:33 [WARNING] BRUTE FORCE DETECTED: 192.168.1.105 — 3 attempts (08:15:33 - 08:15:49)
IT Log Analysis Report
SUMMARY
INFO: 4
WARNING: 4
ERROR: 3
CRITICAL: 1
AI SECURITY ANALYSIS
THREAT LEVEL: HIGH
SUMMARY: Brute force attack detected alongside encryption and AD connectivity failures.
FINDINGS:

Three failed login attempts from 192.168.1.105 within 16 seconds
BitLocker key retrieval failure on DESKTOP-TH4829
Active Directory sync failure — domain controller unreachable
IMMEDIATE ACTIONS:
Isolate 192.168.1.105 and investigate for compromise
Verify domain controller status immediately
Check BitLocker recovery on DESKTOP-TH4829

## Tech Stack

- Python 3
- Anthropic Claude API (Haiku)
- Windows Event Log format