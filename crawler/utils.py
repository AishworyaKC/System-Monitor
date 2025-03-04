import requests
from bs4 import BeautifulSoup

def scan_website(url):
    vulnerabilities = []

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for missing security headers
        missing_headers = []
        security_headers = ["Strict-Transport-Security", "X-Content-Type-Options"]
        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)
        
        if missing_headers:
            vulnerabilities.append(f"Missing HTTP Security Headers: {', '.join(missing_headers)}")

        # Check for outdated software version (Example: Apache)
        server_header = response.headers.get("Server", "")
        if "Apache/2.4.6" in server_header:
            vulnerabilities.append("Outdated Software Version Detected: Apache 2.4.6")

        # Check for forms with GET method instead of POST
        for form in soup.find_all("form"):
            if form.get("method", "").lower() == "get":
                vulnerabilities.append(f"Form without proper method attribute: {form.get('action', 'Unknown Form')}")

    except Exception as e:
        vulnerabilities.append(f"Error scanning website: {str(e)}")

    return vulnerabilities
