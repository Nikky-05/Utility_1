# bridge32.py
import json, glob, os, ctypes, logging, sys
from pkcs11 import lib, Attribute, ObjectClass

logging.basicConfig(level=logging.INFO)

DLLS_32 = [
    r"C:\Windows\System32\eps2003csp11v2.dll",
    r"C:\Windows\SysWOW64\eps2003csp11.dll",
    r"C:\Program Files (x86)\Feitian\ePass2003\eps2003csp11.dll",
    r"C:\Program Files (x86)\CryptoID\CryptoIDA_pkcs11.dll",
    r"C:\Program Files (x86)\WatchData\ProxKey PKI Manager\wdpkcs11.dll"
]
tokens = []
for p in DLLS_32:
    if not os.path.exists(p):
        continue
    try:
        pkcs = lib(p)
        for slot in pkcs.get_slots(token_present=True):
            t = slot.get_token()
            label = t.label.decode("utf-8","ignore") if isinstance(t.label, bytes) else str(t.label)
            serial = t.serial.decode("utf-8","ignore") if isinstance(t.serial, bytes) else str(t.serial)
            tokens.append({"label": label.strip(), "serial": serial.strip(), "library": p})
    except Exception as e:
        logging.info(f"skip {p}: {e}")
print(json.dumps({"tokens": tokens}))
