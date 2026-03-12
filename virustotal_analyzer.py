# Prerequisites
#Python 3.9+ installed.
#A VirusTotal API key (obtainable from the VirusTotal website; free keys have rate limits).
#The requests Python library installed (`pip install requests`).
#Access to the CyberAI Homelab environment (Jupyter Notebook or VS Code).
#Step 1: Setting up the Environment and API Key
#Ensure you have your VirusTotal API key ready. For security, it's best practice not to hardcode API keys directly into scripts that might be shared. Environment variables or a configuration file are better alternatives. For this exercise, we'll use a placeholder.



import requests
import json
import time
import os

# --- Configuration ---
# IMPORTANT: Replace with your actual VirusTotal API key.
# For production, consider using environment variables or a config file.
# Example: VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY' # <<< REPLACE THIS

# API endpoint for retrieving analysis reports
# For files (hashes): https://www.virustotal.com/api/v3/files/{hash}
# For URLs: https://www.virustotal.com/api/v3/urls/{url_id}
# For IPs/Domains: https://www.virustotal.com/api/v3/ip_addresses/{ip_address} or https://www.virustotal.com/api/v3/domains/{domain}

# We will focus on file hashes and IP addresses for this example.

# Rate limiting: Free API allows 4 requests per minute.
# Paid APIs have higher limits.
REQUEST_DELAY_SECONDS = 16 # Slightly more than 60/4 = 15 seconds to be safe

# --- Helper Functions ---
def get_vt_headers():
    """Returns the headers required for VirusTotal API requests."""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'YOUR_VIRUSTOTAL_API_KEY':
        print("\033[91mERROR: VIRUSTOTAL_API_KEY is not set. Please replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual key.\033[0m")
        return None
    return {
        'x-apikey': VIRUSTOTAL_API_KEY
    }

def query_virustotal(resource_id):
    """Queries VirusTotal API for a given file hash or IP address.
    
    Args:
        resource_id (str): The file hash (MD5, SHA1, SHA256) or IP address.
        
    Returns:
        dict: The JSON response from VirusTotal API, or None if an error occurs.
    """
    headers = get_vt_headers()
    if not headers:
        return None

    # Determine the type of resource (hash or IP)
    # A simple check: if it contains dots or is a common IP format, assume IP/domain
    # For simplicity, we'll assume it's a hash if it's not obviously an IP/domain.
    # A more robust check would involve regex or dedicated libraries.
    if '.' in resource_id or ':' in resource_id: # Basic check for IP/domain
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{resource_id}'
        print(f"\033[94mQuerying VirusTotal for IP address: {resource_id}\033[0m")
    else:
        url = f'https://www.virustotal.com/api/v3/files/{resource_id}'
        print(f"\033[94mQuerying VirusTotal for file hash: {resource_id}\033[0m")

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        
        # Respect rate limits
        time.sleep(REQUEST_DELAY_SECONDS)
        
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"\033[91mError querying VirusTotal for {resource_id}: {e}\033[0m")
        if response.status_code == 404:
            print("\033[93mResource not found on VirusTotal. It might be clean or not yet analyzed.\033[0m")
        elif response.status_code == 401:
            print("\033[93mAuthentication error. Check your API key.\033[0m")
        elif response.status_code == 429:
            print("\033[93mRate limit exceeded. Please wait longer between requests or upgrade your API plan.\033[0m")
        return None
    except Exception as e:
        print(f"\033[91mAn unexpected error occurred: {e}\033[0m")
        return None

def process_vt_report(report, resource_id):
    """Processes and displays relevant information from a VirusTotal report.
    
    Args:
        report (dict): The JSON report from VirusTotal API.
        resource_id (str): The file hash or IP address queried.
    """
    if not report or 'data' not in report:
        print(f"\033[93mNo data found or invalid report for {resource_id}.\033[0m")
        return

    print(f"\n--- VirusTotal Analysis Report for: {resource_id} ---")

    # Common data structure for files and IPs/domains
    attributes = report['data']['attributes']

    # --- General Information ---
    print(f"\n[+] General Information:")
    if 'type' in report['data']:
        print(f"  Type: {report['data']['type'].capitalize()}")

    if 'last_analysis_stats' in attributes:
        stats = attributes['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        print(f"  Analysis Stats: Malicious={malicious}, Suspicious={suspicious}, Harmless={harmless}, Undetected={undetected}")

    if 'reputation' in attributes:
        print(f"  Reputation: {attributes['reputation']}")

    if 'tags' in attributes and attributes['tags']:
        print(f"  Tags: {', '.join(attributes['tags'])}")

    # --- File Specific Information ---
    if report['data']['type'] == 'file':
        print(f"\n[+] File Details:")
        if 'meaningful_name' in attributes:
            print(f"  Meaningful Name: {attributes['meaningful_name']}")
        if 'size' in attributes:
            print(f"  Size: {attributes['size']} bytes")
        if 'sha1' in attributes:
            print(f"  SHA1: {attributes['sha1']}")
        if 'sha256' in attributes:
            print(f"  SHA256: {attributes['sha256']}")
        if 'md5' in attributes:
            print(f"  MD5: {attributes['md5']}")
        if 'type_description' in attributes:
            print(f"  File Type: {attributes['type_description']}")
        if 'trid' in attributes and attributes['trid']:
            print(f"  TRID Signatures:")
            for entry in attributes['trid'][:3]: # Show top 3
                print(f"    - {entry['file_type']} ({entry['probability']:.2f}%)")

    # --- IP Address Specific Information ---
    elif report['data']['type'] == 'ip_address':
        print(f"\n[+] IP Address Details:")
        if 'country' in attributes and attributes['country']:
            print(f"  Country: {attributes['country']}")
        if 'as_owner' in attributes and attributes['as_owner']:
            print(f"  ASN Owner: {attributes['as_owner']}")
        if 'last_dns_records' in attributes and attributes['last_dns_records']:
            print(f"  Associated Domains:")
            for record in attributes['last_dns_records'][:5]: # Show top 5
                print(f"    - {record['domain']} (Type: {record['type']})")
        if 'last_http_info' in attributes and attributes['last_http_info']:
            print(f"  Last HTTP Info:")
            http_info = attributes['last_http_info']
            if 'hostname' in http_info:
                print(f"    Hostname: {http_info['hostname']}")
            if 'title' in http_info:
                print(f"    Title: {http_info['title']}")
            if 'http_version' in http_info:
                print(f"    HTTP Version: {http_info['http_version']}")
            if 'status_code' in http_info:
                print(f"    Status Code: {http_info['status_code']}")

    # --- Detailed Analysis Results (from specific engines) ---
    if 'last_analysis' in attributes:
        print(f"\n[+] Detailed Analysis Results (Top 5 Malicious Detections):")
        malicious_engines = []
        for engine, result in attributes['last_analysis'].items():
            if result['category'] == 'malicious':
                malicious_engines.append((engine, result['result']))
        
        # Sort by detection result if available, otherwise just list
        malicious_engines.sort(key=lambda item: item[1] if isinstance(item[1], str) else str(item[1]), reverse=True)
        
        for engine, result in malicious_engines[:5]:
            print(f"  - {engine}: {result}")
        if len(malicious_engines) > 5:
            print(f"  ... and {len(malicious_engines) - 5} more malicious detections.")

    print("--------------------------------------------------")

# --- Main Execution ---
def main():
    print("\033[1mWelcome to the VirusTotal Automated Query Script!\033[0m")
    print("This script queries VirusTotal for file hashes or IP addresses.")
    print("Ensure you have replaced 'YOUR_VIRUSTOTAL_API_KEY' with your actual key.")
    print("\033[93mNote: Free API has rate limits (4 requests/minute). Adjust REQUEST_DELAY_SECONDS if needed.\033[0m")

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'YOUR_VIRUSTOTAL_API_KEY':
        print("\033[91mCRITICAL ERROR: API key not configured. Exiting.\033[0m")
        return

    # Example resources to query
    # You can replace these with actual hashes or IPs you want to check.
    # Example SHA256 hash of a known benign file (e.g., Notepad++ installer)
    example_hash_benign = 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef123456'
    # Example SHA256 hash of a known malicious file (e.g., a sample from malware-traffic-analysis.net)
    example_hash_malicious = 'f1e2d3c4b5a698706543210fedcba9876543210fedcba9876543210fedcba987654'
    # Example IP address (e.g., Google DNS)
    example_ip = '8.8.8.8'
    # Example IP address known for malicious activity (use with caution, may be flagged)
    # example_ip_malicious = '1.2.3.4' # Replace with a known malicious IP if available

    resources_to_check = [
        example_hash_benign,
        example_hash_malicious,
        example_ip
        # Add more hashes or IPs here
    ]

    print("\nStarting automated queries...")
    for resource in resources_to_check:
        report = query_virustotal(resource)
        if report:
            process_vt_report(report, resource)
        else:
            print(f"\033[93mSkipping report processing for {resource} due to query error.\033[0m")

    print("\nAutomated queries finished.")
    print("\033[1mIf you see this message → your lab is working perfectly!\033[0m")

if __name__ == "__main__":
    main()
