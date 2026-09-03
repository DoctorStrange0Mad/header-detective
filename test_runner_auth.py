import os
import sys
import json
import traceback
import mailparser
from auth_checks import check_spf, check_dkim, check_dmarc, get_domain_from_email

def run_tests():
    samples_dir = "samples"
    if not os.path.isdir(samples_dir):
        print(f"Error: {samples_dir} not found.")
        return
        
    for filename in sorted(os.listdir(samples_dir)):
        if not filename.endswith(".eml"):
            continue
            
        filepath = os.path.join(samples_dir, filename)
        print(f"=== Testing: {filename} ===")
        try:
            spf = check_spf(filepath)
            dkim_res = check_dkim(filepath)
            
            mail = mailparser.parse_from_file(filepath)
            from_hdr = mail.headers.get("From")
            from_domain = get_domain_from_email(from_hdr) if from_hdr else None
            
            dmarc = check_dmarc(from_domain, spf.get('domain'), dkim_res.get('domain'))
            
            output = {
                "spf": spf,
                "dkim": dkim_res,
                "dmarc": dmarc
            }
            print(json.dumps(output, indent=2))
        except Exception as e:
            print(f"EXCEPTION ON {filename}: {str(e)}")
            traceback.print_exc()
        print("\n")

if __name__ == "__main__":
    run_tests()
