#Log analyzer
#By A Chinhoyi

import re
import argparse
from collections import defaultdict, Counter
import datetime

# --- Configuration ---

# Example Regex for Apache Combined Log Format:
# 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
# Modify this regex based on the actual log format you need to parse.
LOG_LINE_REGEX = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - .*?'  # IP Address
    r'\[(?P<timestamp>.*?)\] '                             # Timestamp
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+'    # HTTP Method
    r'(?P<path>.*?)\s+'                                    # Requested Path
    r'HTTP/(?P<http_version>\d\.\d)"\s+'                   # HTTP Version
    r'(?P<status_code>\d{3})\s+'                           # Status Code
    r'(?P<size>\d+|-)\s*'                                  # Size
    r'"(?P<referrer>.*?)"\s*'                              # Referrer
    r'"(?P<user_agent>.*?)"'                               # User Agent
)

# --- Rule Definitions ---
# Define rules as functions. Each function takes parsed log data (a dictionary)
# and returns a description of the suspicious event if found, otherwise None.

def rule_multiple_failed_logins(log_entries, threshold=5):
    """
    Identifies IPs with multiple failed login attempts (e.g., HTTP 401 or 403 status codes).
    Note: This requires analyzing multiple log entries together.
    """
    failed_attempts = defaultdict(int)
    suspicious_ips = []

    # Count failed attempts per IP (adjust status codes as needed)
    for entry in log_entries:
        if entry and entry['status_code'] in ['401', '403']:
            failed_attempts[entry['ip']] += 1

    # Check against threshold
    for ip, count in failed_attempts.items():
        if count >= threshold:
            suspicious_ips.append(f"Multiple failed logins ({count} times) detected from IP: {ip}")
    return suspicious_ips

def rule_sql_injection_attempt(log_entry):
    """
    Looks for common SQL injection patterns in the request path/query parameters.
    (This is a basic example, real-world detection is more complex).
    """
    # Simple patterns - extend with more sophisticated regex
    sql_patterns = [
        r'union\s+select', r'insert\s+into', r'select.*from',
        r'drop\s+table', r'or\s+\d+=\d+', r'--', r';', r"'"
    ]
    path = log_entry.get('path', '').lower()
    for pattern in sql_patterns:
        # Use re.search for pattern finding within the path string
        if re.search(pattern, path, re.IGNORECASE):
            return (f"Potential SQL Injection attempt detected in request: "
                    f"{log_entry.get('method')} {log_entry.get('path')} "
                    f"from IP: {log_entry.get('ip')} "
                    f"at {log_entry.get('timestamp')}")
    return None

def rule_directory_traversal(log_entry):
    """
    Looks for directory traversal patterns (e.g., ../).
    """
    path = log_entry.get('path', '')
    if '../' in path or '..\\' in path:
        return (f"Potential Directory Traversal attempt detected: "
                f"{log_entry.get('method')} {log_entry.get('path')} "
                f"from IP: {log_entry.get('ip')} "
                f"at {log_entry.get('timestamp')}")
    return None

def rule_unusual_user_agent(log_entry):
    """
    Flags potentially suspicious or uncommon user agents.
    (Maintain a list of known-bad or suspicious UAs).
    """
    user_agent = log_entry.get('user_agent', '').lower()
    suspicious_ua_keywords = ['sqlmap', 'nmap', 'nikto', 'curl/', 'wget/'] # Example keywords
    for keyword in suspicious_ua_keywords:
        if keyword in user_agent:
            return (f"Suspicious User Agent detected: '{log_entry.get('user_agent')}' "
                    f"from IP: {log_entry.get('ip')} "
                    f"at {log_entry.get('timestamp')}")
    return None

def rule_error_rate(log_entries, threshold_percent=10):
    """
    Flags if the percentage of server errors (5xx) or client errors (4xx) is high.
    """
    total_requests = len(log_entries)
    if total_requests == 0:
        return []

    error_codes_4xx = Counter(entry['status_code'] for entry in log_entries if entry and entry['status_code'].startswith('4'))
    error_codes_5xx = Counter(entry['status_code'] for entry in log_entries if entry and entry['status_code'].startswith('5'))

    total_4xx = sum(error_codes_4xx.values())
    total_5xx = sum(error_codes_5xx.values())

    percent_4xx = (total_4xx / total_requests) * 100
    percent_5xx = (total_5xx / total_requests) * 100

    alerts = []
    if percent_4xx >= threshold_percent:
        alerts.append(f"High client error rate: {percent_4xx:.2f}% ({total_4xx} errors)")
        # You could add details about specific 4xx codes here if needed
    if percent_5xx >= threshold_percent:
        alerts.append(f"High server error rate: {percent_5xx:.2f}% ({total_5xx} errors)")
        # You could add details about specific 5xx codes here if needed

    return alerts


# List of rules to apply (add your rule functions here)
# Some rules analyze individual lines, others analyze the whole dataset
SINGLE_LINE_RULES = [
    rule_sql_injection_attempt,
    rule_directory_traversal,
    rule_unusual_user_agent,
]

MULTI_LINE_RULES = [
    rule_multiple_failed_logins,
    rule_error_rate,
    # Add other rules that need access to all log entries
]

# --- Log Parsing Function ---

def parse_log_line(line):
    """
    Parses a single log line using the defined regex.
    Returns a dictionary of parsed fields or None if parsing fails.
    """
    match = LOG_LINE_REGEX.match(line)
    if match:
        return match.groupdict()
    else:
        # Optionally log lines that didn't match for debugging
        # print(f"Warning: Could not parse line: {line.strip()}")
        return None

# --- Analysis Engine ---

def analyze_logs(log_file_path):
    """
    Reads a log file, parses lines, applies rules, and collects findings.
    """
    suspicious_events = []
    parsed_entries = []
    line_count = 0

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                line_count += 1
                parsed_data = parse_log_line(line)
                if parsed_data:
                    parsed_entries.append(parsed_data)
                    # Apply rules that work on single lines
                    for rule in SINGLE_LINE_RULES:
                        result = rule(parsed_data)
                        if result:
                            suspicious_events.append(f"Line {line_count}: {result}")
                # else: # Handle lines that don't match the regex if necessary
                    # suspicious_events.append(f"Line {line_count}: Unparseable log entry.")


        # Apply rules that need the full context
        for rule in MULTI_LINE_RULES:
            results = rule(parsed_entries) # Pass the list of parsed dictionaries
            if results:
                 # Ensure results are always treated as a list
                if isinstance(results, list):
                    suspicious_events.extend(results)
                else:
                    suspicious_events.append(results) # Append single string result


    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return None, 0
    except Exception as e:
        print(f"An error occurred during log analysis: {e}")
        return None, line_count

    return suspicious_events, line_count

# --- Report Generation ---

def generate_report(findings, total_lines, log_file, report_file):
    """
    Generates a text report summarizing the findings.
    """
    try:
        with open(report_file, 'w') as f:
            f.write("=" * 40 + "\n")
            f.write("       Log Analysis Report\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Report generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Log file analyzed: {log_file}\n")
            f.write(f"Total lines processed: {total_lines}\n")
            f.write(f"Total suspicious events found: {len(findings)}\n\n")
            f.write("-" * 40 + "\n")
            f.write("Suspicious Events Detected:\n")
            f.write("-" * 40 + "\n\n")

            if findings:
                for i, event in enumerate(findings, 1):
                    f.write(f"{i}. {event}\n")
            else:
                f.write("No suspicious events detected based on current rules.\n")

            f.write("\n" + "=" * 40 + "\n")
            f.write("         End of Report\n")
            f.write("=" * 40 + "\n")
        print(f"Report successfully generated: {report_file}")
    except Exception as e:
        print(f"Error writing report file: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious patterns.")
    parser.add_argument("logfile", help="Path to the log file to analyze.")
    parser.add_argument("-o", "--output", default="log_analysis_report.txt",
                        help="Path to the output report file (default: log_analysis_report.txt)")
    # Add more arguments as needed (e.g., rule configuration file, thresholds)

    args = parser.parse_args()

    print(f"Starting log analysis for: {args.logfile}")
    suspicious_findings, lines_processed = analyze_logs(args.logfile)

    if suspicious_findings is not None:
        print(f"Analysis complete. Found {len(suspicious_findings)} suspicious events.")
        generate_report(suspicious_findings, lines_processed, args.logfile, args.output)
    else:
        print("Log analysis could not be completed.")
