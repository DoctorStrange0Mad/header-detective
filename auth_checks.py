import sys
import json
import traceback
import dns.resolver
import dns_cache
dns.resolver.resolve = dns_cache.resolve
import dkim
import checkdmarc
import mailparser
import re
import ipaddress
from hop_parser import extract_ip

def get_domain_from_email(email_str):
    if not email_str:
        return None
    if isinstance(email_str, list):
        if not email_str:
            return None
        email_str = email_str[0]
    if isinstance(email_str, tuple):
        email_str = email_str[1] if len(email_str) > 1 else email_str[0]
    match = re.search(r'@([\w\.-]+)', str(email_str))
    if match:
        return match.group(1).lower().strip('>')
    return None

def _spf_domain(mail):
    return_path = mail.headers.get("Return-Path")
    from_hdr = mail.headers.get("From")

    domain = get_domain_from_email(return_path) if return_path else None
    from_domain = get_domain_from_email(from_hdr) if from_hdr else None

    if domain and '.' not in domain:
        domain = from_domain or domain
    elif not domain:
        domain = from_domain
    return domain

def _public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def _ip_from_headers(mail):
    x_sender = mail.headers.get("X-Sender-IP")
    if x_sender:
        candidate = x_sender.strip() if isinstance(x_sender, str) else str(x_sender[0]).strip()
        if _public_ip(candidate):
            return candidate

    auth_results = mail.headers.get("Authentication-Results", "")
    if isinstance(auth_results, list):
        auth_results = " ".join(auth_results)
    match = re.search(r'client-ip=([0-9a-fA-F\.\:]+)', auth_results, re.I)
    if match and _public_ip(match.group(1)):
        return match.group(1)

    match = re.search(r'sender IP is ([0-9a-fA-F\.\:]+)', auth_results, re.I)
    if match and _public_ip(match.group(1)):
        return match.group(1)
    return None

def get_sender_ip(mail):
    for recv in mail.received:
        from_raw = recv.get('from')
        ip = extract_ip(from_raw)
        if ip and _public_ip(ip):
            return ip
    return _ip_from_headers(mail)

def check_spf(eml_path):
    result_dict = {"result": "none", "domain": None, "details": ""}
    try:
        mail = mailparser.parse_from_file(eml_path)
        
        domain = _spf_domain(mail)
            
        if not domain:
            result_dict["details"] = "No domain found in Return-Path or From"
            return result_dict
            
        result_dict["domain"] = domain
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=3.0)
            spf_record = None
            for rdata in answers:
                txt = b"".join(rdata.strings).decode('utf-8')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break
            
            if not spf_record:
                result_dict["result"] = "none"
                result_dict["details"] = "No SPF record found"
                return result_dict
                
        except dns.resolver.NXDOMAIN:
            result_dict["result"] = "none"
            result_dict["details"] = "NXDOMAIN for domain"
            return result_dict
        except dns.resolver.Timeout:
            result_dict["result"] = "error"
            result_dict["details"] = "DNS timeout"
            return result_dict
        except Exception as e:
            result_dict["result"] = "error"
            result_dict["details"] = f"DNS lookup failed: {str(e)}"
            return result_dict
            
        mechanisms = spf_record.split()[1:]
        supported = ['a', 'mx', 'ip4', 'ip6', 'include', 'all', '~all', '-all', '?all', '+all']
        
        for mech in mechanisms:
            base_mech = mech.split(':')[0].split('=')[0].split('/')[0].lstrip('+?~-')
            if base_mech and base_mech not in supported:
                result_dict["result"] = "error"
                result_dict["details"] = f"unsupported SPF mechanism: {base_mech}"
                return result_dict
                
        sender_ip = get_sender_ip(mail)
        if not sender_ip:
            result_dict["result"] = "neutral"
            result_dict["details"] = "Could not find sender IP to evaluate SPF"
            return result_dict
            
        for mech in mechanisms:
            if mech.startswith('ip4:') or mech.startswith('ip6:'):
                subnet = mech.split(':', 1)[1]
                try:
                    if ipaddress.ip_address(sender_ip) in ipaddress.ip_network(subnet, strict=False):
                        result_dict["result"] = "pass"
                        result_dict["details"] = f"Matched {mech}"
                        return result_dict
                except:
                    pass
            elif mech == 'include:' or mech.startswith('include:'):
                inc_domain = mech.split(':', 1)[1]
                try:
                    inc_answers = dns.resolver.resolve(inc_domain, 'TXT', lifetime=3.0)
                    for rdata in inc_answers:
                        inc_txt = b"".join(rdata.strings).decode('utf-8')
                        if inc_txt.startswith("v=spf1"):
                            for inc_mech in inc_txt.split()[1:]:
                                if inc_mech.startswith('ip4:') or inc_mech.startswith('ip6:'):
                                    subnet = inc_mech.split(':', 1)[1]
                                    try:
                                        if ipaddress.ip_address(sender_ip) in ipaddress.ip_network(subnet, strict=False):
                                            result_dict["result"] = "pass"
                                            result_dict["details"] = f"Matched {inc_mech} in include:{inc_domain}"
                                            return result_dict
                                    except:
                                        pass
                except:
                    pass

        if mechanisms and mechanisms[-1] == '-all':
            result_dict["result"] = "fail"
        elif mechanisms and mechanisms[-1] == '~all':
            result_dict["result"] = "softfail"
        else:
            result_dict["result"] = "neutral"
            
        result_dict["details"] = f"SPF evaluated to {result_dict['result']}"
            
    except Exception as e:
        result_dict["result"] = "error"
        result_dict["details"] = f"Exception: {str(e)}"
        
    return result_dict

def check_dkim(eml_path):
    result_dict = {"result": "none", "selector": None, "domain": None}
    try:
        with open(eml_path, 'rb') as f:
            raw_email = f.read()
            
        mail = mailparser.parse_from_file(eml_path)
        from_hdr = mail.headers.get("From")
        from_domain = get_domain_from_email(from_hdr) if from_hdr else None
        
        try:
            d = dkim.DKIM(raw_email)
            if not d.headers:
                result_dict["result"] = "none"
                return result_dict
                
            has_dkim = any(hdr.lower() == b'dkim-signature' for hdr, val in d.headers)
            if not has_dkim:
                result_dict["result"] = "none"
                return result_dict
                
            sig_to_verify = None
            for hdr, val in d.headers:
                if hdr.lower() == b'dkim-signature':
                    sig_str = val.decode('utf-8', errors='ignore')
                    match_d = re.search(r'd=([^;\s]+)', sig_str)
                    match_s = re.search(r's=([^;\s]+)', sig_str)
                    d_domain = match_d.group(1) if match_d else None
                    selector = match_s.group(1) if match_s else None
                    
                    if d_domain and from_domain and d_domain.lower() == from_domain.lower():
                        sig_to_verify = (d_domain, selector)
                        break
                        
            if not sig_to_verify:
                for hdr, val in d.headers:
                    if hdr.lower() == b'dkim-signature':
                        sig_str = val.decode('utf-8', errors='ignore')
                        match_d = re.search(r'd=([^;\s]+)', sig_str)
                        match_s = re.search(r's=([^;\s]+)', sig_str)
                        d_domain = match_d.group(1) if match_d else None
                        selector = match_s.group(1) if match_s else None
                        sig_to_verify = (d_domain, selector)
                        break
                        
            if sig_to_verify:
                result_dict["domain"] = sig_to_verify[0]
                result_dict["selector"] = sig_to_verify[1]
                
            res = dkim.verify(raw_email)
            if res:
                result_dict["result"] = "pass"
            else:
                result_dict["result"] = "fail"
                
        except Exception as e:
            if "no signature" in str(e).lower():
                result_dict["result"] = "none"
            else:
                result_dict["result"] = "fail"
                
    except Exception as e:
        result_dict["result"] = "error"
        
    return result_dict

def check_dmarc(domain, spf_domain=None, dkim_domain=None):
    result_dict = {
        "result": "none",
        "policy": None,
        "alignment": {"spf": False, "dkim": False}
    }
    
    if not domain:
        return result_dict
        
    try:
        def check_align(d1, d2):
            if not d1 or not d2:
                return False
            try:
                from checkdmarc.utils import get_base_domain
                return get_base_domain(d1.lower()) == get_base_domain(d2.lower())
            except:
                return d1.lower().endswith(d2.lower()) or d2.lower().endswith(d1.lower())
                
        result_dict["alignment"]["spf"] = check_align(domain, spf_domain)
        result_dict["alignment"]["dkim"] = check_align(domain, dkim_domain)
        
        try:
            dmarc_res = checkdmarc.check_dmarc(domain)
            if 'record' in dmarc_res and dmarc_res['record']:
                match = re.search(r'p=([^;\s]+)', dmarc_res['record'])
                if match:
                    result_dict["policy"] = match.group(1).lower()
                    result_dict["result"] = "pass"
                else:
                    result_dict["result"] = "none"
            elif 'parsed' in dmarc_res and dmarc_res['parsed'] and 'tags' in dmarc_res['parsed']:
                policy = dmarc_res['parsed']['tags'].get('p', {}).get('value')
                if policy:
                    result_dict["policy"] = policy.lower()
                    result_dict["result"] = "pass"
                else:
                    result_dict["result"] = "none"
            else:
                result_dict["result"] = "none"
        except Exception:
            try:
                import publicsuffixlist
                answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT', lifetime=3.0)
                for rdata in answers:
                    txt = b"".join(rdata.strings).decode('utf-8')
                    if txt.startswith("v=DMARC1"):
                        match = re.search(r'p=([^;\s]+)', txt)
                        if match:
                            result_dict["policy"] = match.group(1).lower()
                            result_dict["result"] = "pass"
                            return result_dict
                result_dict["result"] = "none"
            except:
                result_dict["result"] = "none"
            
    except Exception as e:
        pass
        
    return result_dict

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python auth_checks.py <filepath>")
        sys.exit(1)
        
    filepath = sys.argv[1]
    
    print("--- SPF ---")
    spf = check_spf(filepath)
    print(json.dumps(spf, indent=2))
    
    print("\n--- DKIM ---")
    dkim_res = check_dkim(filepath)
    print(json.dumps(dkim_res, indent=2))
    
    print("\n--- DMARC ---")
    mail = mailparser.parse_from_file(filepath)
    from_hdr = mail.headers.get("From")
    from_domain = get_domain_from_email(from_hdr) if from_hdr else None
    
    dmarc = check_dmarc(from_domain, spf.get('domain'), dkim_res.get('domain'))
    print(json.dumps(dmarc, indent=2))
