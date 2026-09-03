import json
import hashlib
from datetime import datetime, timezone

def generate_fake_output():
    """Generates fake JSON output matching the required schema."""
    fake_data = {
        "file_hash_sha256": hashlib.sha256(b"dummy_content").hexdigest(),
        "hops": [
            {
                "hop_index": 0,
                "from_host": "mail.example.com",
                "from_ip": "192.168.1.100",
                "by_host": "mx.receiver.com",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "protocol": "ESMTPS"
            },
            {
                "hop_index": 1,
                "from_host": "mx.receiver.com",
                "from_ip": "10.0.0.5",
                "by_host": "internal.receiver.com",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "protocol": "SMTP"
            }
        ],
        "auth": {
            "spf": {
                "result": "pass",
                "domain": "example.com",
                "details": "example.com: domain of sender@example.com designates 192.168.1.100 as permitted sender"
            },
            "dkim": {
                "result": "pass",
                "selector": "s1",
                "domain": "example.com"
            },
            "dmarc": {
                "result": "pass",
                "policy": "reject",
                "alignment": {
                    "spf": True,
                    "dkim": True
                }
            }
        },
        "sender_domain": "example.com",
        "warnings": [
            "Warning: this is fake dummy output."
        ]
    }
    return json.dumps(fake_data, indent=2)

if __name__ == "__main__":
    print(generate_fake_output())
