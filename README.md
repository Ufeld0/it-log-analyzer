# IT Log Analyzer

AI-powered Windows log analysis tool for IT Security teams.

Parses system logs, identifies critical events, and generates security analysis using Claude AI (Anthropic).

## Features

- Parses structured Windows log files
- Filters WARNING, ERROR, and CRITICAL events
- Detects patterns: brute force attempts, cascading failures, AD issues
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

```bash
# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

## Tech Stack

- Python 3
- Anthropic Claude API (Haiku)
- Windows Event Log format