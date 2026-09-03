import sys
import json
import time
from main import process_email
import dns_cache

def test_cache():
    filepath = "samples/sample-1004.eml"
    
    start1 = time.time()
    out1 = process_email(filepath)
    time1 = time.time() - start1
    
    start2 = time.time()
    out2 = process_email(filepath)
    time2 = time.time() - start2
    
    # Assert identical
    json1 = json.dumps(out1, indent=2)
    json2 = json.dumps(out2, indent=2)
    
    print(f"Run 1 Time: {time1:.3f}s")
    print(f"Run 2 Time: {time2:.3f}s")
    
    if json1 == json2:
        print("Outputs are IDENTICAL.")
    else:
        print("Outputs DIFFER!")
        
    print(f"Cache size: {len(dns_cache._cache)}")

if __name__ == "__main__":
    test_cache()
