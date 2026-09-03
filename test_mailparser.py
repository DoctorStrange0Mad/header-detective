import mailparser
import sys
import json

def test():
    mail = mailparser.parse_from_file(sys.argv[1])
    print(json.dumps(mail.received, indent=2))
    print(json.dumps(mail.headers.get("Received", []), indent=2))

if __name__ == "__main__":
    test()
