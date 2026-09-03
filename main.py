import sys
import json
import hashlib
import traceback
import os
import mailparser

from hop_parser import parse_hops
from auth_checks import check_spf, check_dkim, check_dmarc, get_domain_from_email

def validate_schema(data):
    try:
        assert isinstance(data, dict)
        assert isinstance(data.get("file_hash_sha256"), str)
        assert len(data["file_hash_sha256"]) == 64
        
        assert isinstance(data.get("hops"), list)
        for hop in data["hops"]:
            assert isinstance(hop.get("hop_index"), int)
            assert isinstance(hop.get("from_host"), (str, type(None)))
            assert isinstance(hop.get("from_ip"), (str, type(None)))
            assert isinstance(hop.get("by_host"), (str, type(None)))
            assert isinstance(hop.get("timestamp"), (str, type(None)))
            assert isinstance(hop.get("protocol"), (str, type(None)))
            
        auth = data.get("auth", {})
        assert isinstance(auth, dict)
        
        spf = auth.get("spf", {})
        assert spf.get("result") in ["pass", "fail", "softfail", "neutral", "none", "error"]
        assert isinstance(spf.get("domain"), (str, type(None)))
        assert isinstance(spf.get("details"), str)
        
        dkim = auth.get("dkim", {})
        assert dkim.get("result") in ["pass", "fail", "none", "error"]
        assert isinstance(dkim.get("selector"), (str, type(None)))
        assert isinstance(dkim.get("domain"), (str, type(None)))
        
        dmarc = auth.get("dmarc", {})
        assert dmarc.get("result") in ["pass", "fail", "none"]
        assert dmarc.get("policy") in ["none", "quarantine", "reject", None]
        alignment = dmarc.get("alignment", {})
        assert isinstance(alignment.get("spf"), bool)
        assert isinstance(alignment.get("dkim"), bool)
        
        assert isinstance(data.get("sender_domain"), (str, type(None)))
        assert isinstance(data.get("warnings"), list)
        for w in data["warnings"]:
            assert isinstance(w, str)
            
        return True
    except AssertionError as e:
        print(f"SCHEMA VALIDATION FAILED: {str(e)}")
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"SCHEMA VALIDATION CRASHED: {str(e)}")
        return False

def process_email(filepath):
    output = {
        "file_hash_sha256": "0" * 64,
        "hops": [],
        "auth": {
            "spf": {"result": "none", "domain": None, "details": ""},
            "dkim": {"result": "none", "selector": None, "domain": None},
            "dmarc": {"result": "none", "policy": None, "alignment": {"spf": False, "dkim": False}}
        },
        "sender_domain": None,
        "warnings": []
    }
    
    try:
        # Compute SHA-256
        with open(filepath, 'rb') as f:
            raw_bytes = f.read()
        output["file_hash_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
        
        # Parse hops
        try:
            hops, hop_warnings = parse_hops(filepath)
            output["hops"] = hops
            output["warnings"].extend(hop_warnings)
        except Exception as e:
            output["warnings"].append(f"Hops parser crashed: {str(e)}")
            
        # Get sender domain
        try:
            mail = mailparser.parse_from_file(filepath)
            from_hdr = mail.headers.get("From")
            output["sender_domain"] = get_domain_from_email(from_hdr)
        except Exception as e:
            output["warnings"].append(f"Sender domain extraction crashed: {str(e)}")
            
        # Auth checks
        try:
            output["auth"]["spf"] = check_spf(filepath)
        except Exception as e:
            output["auth"]["spf"]["result"] = "error"
            output["auth"]["spf"]["details"] = str(e)
            output["warnings"].append(f"SPF check crashed: {str(e)}")
            
        try:
            output["auth"]["dkim"] = check_dkim(filepath)
        except Exception as e:
            output["auth"]["dkim"]["result"] = "error"
            output["warnings"].append(f"DKIM check crashed: {str(e)}")
            
        try:
            output["auth"]["dmarc"] = check_dmarc(
                output["sender_domain"], 
                output["auth"]["spf"].get("domain"), 
                output["auth"]["dkim"].get("domain")
            )
        except Exception as e:
            output["auth"]["dmarc"]["result"] = "none"
            output["warnings"].append(f"DMARC check crashed: {str(e)}")

    except Exception as e:
        output["warnings"].append(f"Unhandled internal error during processing: {str(e)}")
        
    if not validate_schema(output):
        output["warnings"].append("BUG: Output failed schema validation")
        print("BUG: Output failed schema validation", file=sys.stderr)
        
    return output

def run_batch():
    samples_dir = "samples"
    if not os.path.isdir(samples_dir):
        print(f"Error: {samples_dir} not found.")
        return
        
    summary = []
    
    for filename in sorted(os.listdir(samples_dir)):
        if not filename.endswith(".eml"):
            continue
            
        filepath = os.path.join(samples_dir, filename)
        try:
            output = process_email(filepath)
            valid = validate_schema(output)
            summary.append({
                "filename": filename,
                "valid": valid,
                "hops": len(output["hops"]),
                "spf": output["auth"]["spf"]["result"],
                "dkim": output["auth"]["dkim"]["result"],
                "dmarc": output["auth"]["dmarc"]["result"],
                "warnings": len(output["warnings"])
            })
        except Exception as e:
            summary.append({
                "filename": filename,
                "valid": False,
                "hops": 0,
                "spf": "error",
                "dkim": "error",
                "dmarc": "none",
                "warnings": 1
            })
            print(f"FATAL EXCEPTION ON {filename}: {str(e)}")
            
    print("\n" + "="*80)
    print(f"{'Filename':<55} | {'Valid':<5} | {'Hops':<4} | {'SPF':<8} | {'DKIM':<8} | {'DMARC':<5} | {'Warns'}")
    print("="*80)
    for s in summary:
        print(f"{s['filename'][:53]:<55} | {str(s['valid']):<5} | {s['hops']:<4} | {s['spf']:<8} | {s['dkim']:<8} | {s['dmarc']:<5} | {s['warnings']}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        result = process_email(filepath)
        
        out_dir = "outputs"
        os.makedirs(out_dir, exist_ok=True)
        
        base_name = os.path.basename(filepath)
        name_without_ext = os.path.splitext(base_name)[0]
        out_path = os.path.join(out_dir, f"{name_without_ext}.json")
        
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
            
        print(f"Successfully saved JSON to {out_path}")
        # Also print to stdout for teammates who might still be piping it
        print(json.dumps(result, indent=2))
    else:
        run_batch()
