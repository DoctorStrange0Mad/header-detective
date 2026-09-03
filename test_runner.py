import os
import sys
import json
from hop_parser import parse_hops
import traceback

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
            hops, warnings = parse_hops(filepath)
            output = {
                "hops": hops,
                "warnings": warnings
            }
            print(json.dumps(output, indent=2))
        except Exception as e:
            print(f"EXCEPTION ON {filename}: {str(e)}")
            traceback.print_exc()
        print("\n")

if __name__ == "__main__":
    run_tests()
