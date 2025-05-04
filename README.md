# Python Log Analyzer for Suspicious Activity

## Overview

This repository contains a Python script designed to parse log files, identify potentially suspicious events based on predefined rules, and generate a concise report. It serves as a practical example of log analysis techniques often used in cybersecurity monitoring and incident response.

This script is intended as a foundational tool and a portfolio piece, demonstrating basic log parsing, rule-based detection, and reporting capabilities.

## Features

* **Log Parsing:** Parses log lines based on a configurable regular expression (currently configured for Apache Combined Log Format).
* **Rule-Based Detection:** Includes example rules to detect:
    * Multiple failed login attempts from the same IP address.
    * Potential SQL injection attempts in request paths.
    * Potential directory traversal attempts.
    * Usage of suspicious User-Agents often associated with scanning tools.
    * High rates of client-side (4xx) or server-side (5xx) errors.
* **Reporting:** Generates a simple text-based summary report (`.txt`) detailing the findings, including the log file analyzed, total lines processed, and a list of detected suspicious events.
* **Command-Line Interface:** Accepts the log file path and an optional output report file path as command-line arguments.

## Requirements

* Python 3.x

## Installation

No installation is required beyond having Python 3. Simply clone this repository or download the `log_analyzer.py` script.

```bash

Usage
Run the script from your terminal, providing the path to the log file you want to analyze.

python log_analyzer.py <path_to_your_log_file.log> [options]

Arguments:

logfile: (Required) The path to the log file to be analyzed.

-o or --output: (Optional) The path where the output report file should be saved. Defaults to log_analysis_report.txt in the current directory.

Example:

# Analyze 'access.log' and save the report to the default 'log_analysis_report.txt'
python log_analyzer.py /var/log/apache2/access.log

# Analyze 'example.log' (included in this repo) and save to 'my_custom_report.txt'
python log_analyzer.py example.log -o my_custom_report.txt

The script will print status messages to the console and generate the report file upon completion.

Customization
Log Format: Modify the LOG_LINE_REGEX variable in log_analyzer.py to match the specific format of the logs you need to parse (e.g., Nginx, firewall logs, application logs). You'll need to adjust the named capture groups (?P<name>...) accordingly.

Rules:

Modify existing rule functions (e.g., change thresholds, update SQL patterns, add more suspicious user agents).

Add new rule functions to detect different types of events. Remember to add your new function name to either the SINGLE_LINE_RULES or MULTI_LINE_RULES list depending on whether it analyzes individual lines or the entire dataset.

Output Format: Modify the generate_report function to change the report format (e.g., CSV, JSON).

Example Log File
An example.log file is included in this repository to demonstrate the script's functionality with various suspicious patterns.

Future Enhancements / Potential Improvements
Support for multiple log formats via configuration files or format auto-detection.

More sophisticated rule engine (e.g., using YAML for rule definitions).

Integration with external threat intelligence feeds (e.g., lists of known malicious IPs).

Time-based correlation rules (e.g., detecting brute-force attacks over specific time windows).

Output to different formats (JSON, CSV, HTML).

Adding unit tests for parsing and rule logic.

