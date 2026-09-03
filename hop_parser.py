import sys
import json
import re
import mailparser
from dateutil import parser as date_parser
from dateutil import tz as date_tz

def extract_ip(from_str):
    if not from_str:
        return None
    match = re.search(r'\[([0-9a-fA-F\.\:]+)\]', from_str)
    if match:
        return match.group(1)
    
    # Check if the host itself is just an IP
    host_match = re.match(r'^([^\s\(]+)', from_str)
    if host_match:
        host = host_match.group(1)
        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', host) or re.match(r'^[0-9a-fA-F\:]+$', host):
            return host
    return None

def extract_host(from_str):
    if not from_str:
        return None
    # Usually the first token before space or parentheses is the host
    match = re.match(r'^([^\s\(]+)', from_str)
    if match:
        return match.group(1)
    return from_str

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
