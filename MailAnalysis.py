import re
import sys
import quopri
import hashlib
import ipaddress
import requests
import email

def read_file(file_path):
    """Read and parse an email file."""
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        parser = email.parser.BytesParser()
        return parser.parsebytes(content)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        sys.exit(1)

def extract_ips(email_message):
    """Extract valid IP addresses from email headers and body."""
    ips = set()
    
    # Extract IPs from headers
    for header_name, header_value in email_message.items():
        if header_value:
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
    
    # Extract IPs from email body
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type in ['text/plain', 'text/html']:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except:
                    continue
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
    
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass
    return list(set(valid_ips))

def extract_urls(email_message):
    """Extract URLs from email body."""
    urls = set()
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type in ['text/plain', 'text/html']:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except:
                    continue
            urls.update(re.findall(r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', payload))
    return list(urls)

def defang_ip(ip):
    """Defang IP address for safe display."""
    return ip.replace('.', '[.]')

def defang_url(url):
    """Defang URL for safe display."""
    url = url.replace('https://', 'hxxps[://]')
    url = url.replace('http://', 'hxxp[://]')
    return url.replace('.', '[.]')

def is_reserved_ip(ip):
    """Check if IP is in private or reserved ranges."""
    private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    reserved_ranges = [
        '0.0.0.0/8',
        '127.0.0.1',
        '100.64.0.0/10',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4', 
        '240.0.0.0/4',
    ]
    try:
        ip_addr = ipaddress.ip_address(ip)
        for r in private_ranges + reserved_ranges:
            if ip_addr in ipaddress.ip_network(r):
                return True
    except ValueError:
        return False
    return False

def ip_lookup(ip):
    """Perform IP lookup using ipinfo.io API."""
    if is_reserved_ip(ip):
        return None

    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'IP': data.get('ip', ''),
                'City': data.get('city', 'Unknown'),
                'Region': data.get('region', 'Unknown'),
                'Country': data.get('country', 'Unknown'),
                'Location': data.get('loc', 'Unknown'),
                'ISP': data.get('org', 'Unknown'),
                'Postal Code': data.get('postal', 'Unknown')
            }
    except (requests.RequestException, ValueError):
        return None
    return None

def extract_headers(email_message):
    """Extract relevant email headers."""
    headers_to_extract = [
        "Date",
        "Subject",
        "To",
        "From",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "X-Originating-IP",
        "X-Sender-IP",
        "Authentication-Results"
    ]
    headers = {}
    for key in email_message.keys():
        if key in headers_to_extract and email_message[key]:
            headers[key] = email_message[key]
    return headers

def extract_attachments(email_message):
    """Extract attachment details with file hashes."""
    attachments = []
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            if payload:
                attachments.append({
                    'filename': filename,
                    'md5': hashlib.md5(payload).hexdigest(),
                    'sha1': hashlib.sha1(payload).hexdigest(),
                    'sha256': hashlib.sha256(payload).hexdigest()
                })
    return attachments

def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 50)
    print(f"{title}")
    print("=" * 50)

def main(file_path):
    """Main function to analyze email file."""
    print("\n" + "#" * 50)
    print(f"Komy's Email Analysis Tool v1.0")
    print("#" * 50)
    
    email_message = read_file(file_path)

     # Extract and display headers
    headers = extract_headers(email_message)
    print_section("Extracted Headers")
    if not headers:
        print("No relevant headers found.")
    for key, value in headers.items():
        print(f"{key}: {value}")
    
    # Extract and display IPs
    ips = extract_ips(email_message)
    print_section("Extracted IP Addresses")
    if not ips:
        print("No IP addresses found.")
    for ip in ips:
        defanged_ip = defang_ip(ip)
        ip_info = ip_lookup(ip)
        if ip_info:
            print(f"IP: {defanged_ip}")
            print(f"  City: {ip_info['City']}")
            print(f"  Region: {ip_info['Region']}")
            print(f"  Country: {ip_info['Country']}")
            print(f"  ISP: {ip_info['ISP']}")
            print()
        else:
            print(f"IP: {defanged_ip} (No info available or reserved IP)")

    # Extract and display URLs
    urls = extract_urls(email_message)
    print_section("Extracted URLs")
    if not urls:
        print("No URLs found.")
    for url in urls:
        print(defang_url(url))


    # Extract and display attachments
    attachments = extract_attachments(email_message)
    print_section("Extracted Attachments")
    if not attachments:
        print("No attachments found.")
    for attachment in attachments:
        print(f"Filename: {attachment['filename']}")
        print(f"MD5: {attachment['md5']}")
        print(f"SHA1: {attachment['sha1']}")
        print(f"SHA256: {attachment['sha256']}")
        print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python komy_email_analyzer.py <file_path>")
        print("Komy's Email Analysis Tool v1.0")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)