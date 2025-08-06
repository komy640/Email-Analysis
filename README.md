# Email-Analysis

This Python script is designed to aid in email forensic analysis by extracting various components from email files such as IP addresses, URLs, headers, and attachments.

## Features:
- **IP Address Extraction**: Identifies and extracts IP addresses from the email content in defanged format.
- **URL Extraction**: Extracts URLs from the email content in defanged format.
- **Header Extraction**: Retrieves common useful email headers to aid in sender attribution.
- **Attachment Extraction**: Parses email attachments and provides details such as filename, MD5, SHA1, and SHA256 hashes.

## Additional Functionalities:
- **IP and URL Defanging**: Defangs IP addresses and URLs, making them safer for analysis.
- **IP Information Lookup**: Utilizes the `ipinfo.io` API to gather information about IP addresses, including city, region, country, and ISP.

## Requirements

```bash
pip3 install -r requirements.txt
```

## Usage
```bash
python3 MailAnalysis.py <file_path>
```

## Example:
![Uploading WhatsApp Image 2025-08-06 at 12.06.57_b4da0468.jpg…]()







