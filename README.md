[README.md](https://github.com/user-attachments/files/31772765/README.md)
# Header Detective

Parses `.eml` email files for SPF/DKIM/DMARC results and relay hop info.

## Tools & Dependencies

- Python 3.13
- [mailparser](https://pypi.org/project/mail-parser/) — .eml parsing
- [dnspython](https://pypi.org/project/dnspython/) — DNS resolution
- [dkimpy](https://pypi.org/project/dkimpy/) — DKIM verification
- [checkdmarc](https://pypi.org/project/checkdmarc/) — DMARC verification
- [python-dateutil](https://pypi.org/project/python-dateutil/) — timestamp parsing
- [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/) — REST API (`api.py`)
- [python-multipart](https://pypi.org/project/python-multipart/) — file uploads for FastAPI

Install:

```bash
pip install mailparser dnspython dkimpy checkdmarc python-dateutil fastapi uvicorn python-multipart
```
