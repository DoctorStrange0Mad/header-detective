import sys
import json
import re
import ipaddress
import mailparser
from dateutil import parser as date_parser
from dateutil import tz as date_tz

def _valid_ip(candidate):
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False

def extract_ip(from_str):
    if not from_str:
        return None

    match = re.search(r'\[([0-9a-fA-F\.\:]+)\]', from_str)
    if match and _valid_ip(match.group(1)):
        return match.group(1)

    for match in re.finditer(r'\(([0-9a-fA-F\.\:]+)\)', from_str):
        candidate = match.group(1)
        if _valid_ip(candidate):
            return candidate

    host_match = re.match(r'^([^\s\(\[]+|\[[0-9a-fA-F\.\:]+\])', from_str)
    if host_match:
        host = host_match.group(1).strip('[]')
        if _valid_ip(host):
            return host
    return None

def extract_host(from_str):
    if not from_str:
        return None

    if re.search(r'\buserid\s+\d+\)', from_str, re.I):
        return None

    helo_match = re.search(r'\bhelo=([^\s\)]+)', from_str, re.I)
    if helo_match:
        return helo_match.group(1)

    match = re.match(r'^([^\s\(]+)', from_str)
    if match:
        host = match.group(1).strip('[]')
        if _valid_ip(host):
            return None
        return host
    return None

def parse_hops(filepath):
    warnings = []
    hops = []
    
    try:
        mail = mailparser.parse_from_file(filepath)
    except Exception as e:
        warnings.append(f"Failed to parse email file {filepath}: {str(e)}")
        return hops, warnings

    received_headers = mail.headers.get("Received", [])
    
    for i, recv in enumerate(mail.received):
        hop = {
            "hop_index": i,
            "from_host": None,
            "from_ip": None,
            "by_host": None,
            "timestamp": None,
            "protocol": None
        }
        
        try:
            from_raw = recv.get("from")
            hop["from_host"] = extract_host(from_raw) if from_raw else None
            hop["from_ip"] = extract_ip(from_raw) if from_raw else None
            hop["by_host"] = recv.get("by")
            hop["protocol"] = recv.get("with")
            
            date_utc = recv.get("date_utc")
            date_str = recv.get("date")
            
            if date_utc:
                hop["timestamp"] = date_utc
            elif date_str:
                try:
                    parsed_date = date_parser.parse(date_str)
                    hop["timestamp"] = parsed_date.astimezone(date_tz.tzutc()).isoformat()
                except Exception as e:
                    warnings.append(f"hop_index {i}: could not parse timestamp '{date_str}' - {str(e)}")
            
            if not any([hop["from_host"], hop["by_host"], hop["timestamp"]]):
                warnings.append(f"hop_index {i}: could not parse Received header properly")
                
        except Exception as e:
            warnings.append(f"hop_index {i}: exception while extracting hop data - {str(e)}")
            
        hops.append(hop)
        
    if not mail.received and received_headers:
        if isinstance(received_headers, str):
            received_headers = [received_headers]
            
        for i, raw_hdr in enumerate(received_headers):
            warnings.append(f"hop_index {i}: could not parse Received header (mailparser failure)")
            hops.append({
                "hop_index": i,
                "from_host": None,
                "from_ip": None,
                "by_host": None,
                "timestamp": None,
                "protocol": None
            })
            
    return hops, warnings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hop_parser.py <filepath>")
        sys.exit(1)
        
    filepath = sys.argv[1]
    hops, warnings = parse_hops(filepath)
    output = {
        "hops": hops,
        "warnings": warnings
    }
    print(json.dumps(output, indent=2))
