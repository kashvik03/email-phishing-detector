import re

def load_blacklist(file_path):
    with open(file_path, 'r') as f:
        return set(ip.strip() for ip in f.readlines())

def extract_received_ips(header_text):
    return re.findall(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', header_text)

def detect_spoofed_domain(header_text):
    from_match = re.search(r"From:\s?.*<(.+?)>", header_text)
    return_path_match = re.search(r"Return-Path:\s?<(.+?)>", header_text)

    if from_match and return_path_match:
        from_domain = from_match.group(1).split('@')[-1]
        return_path_domain = return_path_match.group(1).split('@')[-1]
        return from_domain != return_path_domain
    return False

def analyze_header(header_path, blacklist_path):
    with open(header_path, 'r') as f:
        header = f.read()

    blacklisted_ips = load_blacklist(blacklist_path)
    received_ips = extract_received_ips(header)

    spoofed = detect_spoofed_domain(header)
    blacklisted = any(ip in blacklisted_ips for ip in received_ips)

    print(f"\nAnalyzing: {header_path}")
    print(f"-> Spoofed Domain: {'Yes' if spoofed else 'No'}")
    print(f"-> Blacklisted IP Found: {'Yes' if blacklisted else 'No'}")
    print(f"-> Received IPs: {received_ips}")

if __name__ == "__main__":
    analyze_header("sample_headers/example1.txt", "blacklisted_ips.txt")
