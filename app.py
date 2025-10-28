from flask import Flask, jsonify, render_template, request
from pkcs11 import lib, Attribute, ObjectClass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ctypes, os, platform, subprocess, json, glob, threading, time
from ctypes import wintypes

app = Flask(__name__, template_folder="templates")

last_detected_tokens = []
last_scan_time = 0


#  Check Python architecture
def is_64bit_python():
    return platform.architecture()[0] == "64bit"


# Detect DLL bitness
def is_dll_64bit(path):
    try:
        with open(path, 'rb') as f:
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), 'little')
            f.seek(pe_offset + 4)
            machine = int.from_bytes(f.read(2), 'little')
            return machine == 0x8664
    except Exception:
        return None


#  Find PKCS#11 libraries dynamically
def find_pkcs11_libraries():
    search_paths = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files",
        r"C:\Program Files (x86)"
    ]
    patterns = [
        "*pkcs11*.dll",
        "*eps2003*.dll",
        "*wdpkcs11*.dll",
        "*CryptoID*.dll",
        "*token*.dll",
        "*IDPrime*.dll",
    ]
    found = []
    for base in search_paths:
        for pattern in patterns:
            found += glob.glob(os.path.join(base, "**", pattern), recursive=True)
    return list(dict.fromkeys(found))


#  Detect valid libraries
def detect_libraries():
    print(f"\n🔍 Scanning PKCS#11 libraries for {platform.architecture()[0]} Python...\n")
    all_libs = find_pkcs11_libraries()
    valid_libs, bit32_libs = [], []

    for dll_path in all_libs:
        try:
            dll = ctypes.WinDLL(dll_path)
            if hasattr(dll, "C_GetFunctionList"):
                dll_64 = is_dll_64bit(dll_path)
                if dll_64 is None:
                    continue
                if dll_64:
                    valid_libs.append(dll_path)
                else:
                    bit32_libs.append(dll_path)
        except Exception:
            continue

    if is_64bit_python():
        if valid_libs:
            return valid_libs, []
        else:
            print("⚠️ No 64-bit DLLs found. Trying 32-bit bridge...")
            return [], bit32_libs
    else:
        if bit32_libs:
            return bit32_libs, []
        else:
            print("⚠️ No 32-bit DLLs found. Trying 64-bit fallback...")
            return valid_libs, []


# Token reader
def read_pkcs11_tokens():
    valid_libs, bit32_libs = detect_libraries()
    tokens = []

    for dll_path in valid_libs:
        try:
            pkcs11 = lib(dll_path)
            for slot in pkcs11.get_slots(token_present=True):
                token = slot.get_token()
                tokens.append({
                    "label": str(token.label).strip(),
                    "serial": str(token.serial).strip(),
                    "manufacturer": str(token.manufacturer_id).strip(),
                    "library": dll_path,
                    "source": "PKCS#11"
                })
        except Exception as e:
            print("Error reading token:", e)
            continue

    # 32-bit fallback
    if not tokens and bit32_libs:
        python32 = os.getenv("PYTHON32_PATH", r"C:\Users\hp\AppData\Local\Programs\Python\Python315-32\python.exe")
        if os.path.exists(python32):
            result = subprocess.run([python32, "bridge32.py"], capture_output=True, text=True)
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for t in data.get("tokens", []):
                        t["source"] = "PKCS#11 (32-bit bridge)"
                    tokens.extend(data.get("tokens", []))
                except Exception:
                    pass
    return tokens


# CSP fallback
def read_csp_tokens():
    print("Scanning CSP/SmartCard subsystem...")
    tokens = []
    try:
        result = subprocess.run(["certutil", "-user", "-store", "My"],
                                capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            if "Provider =" in line or "WatchData" in line or "ePass" in line or "SafeNet" in line:
                name = line.split("=")[-1].strip()
                tokens.append({
                    "label": name,
                    "serial": "N/A",
                    "manufacturer": "SmartCard CSP",
                    "library": "CSP",
                    "source": "CSP"
                })
    except subprocess.TimeoutExpired:
        print(" CSP scan timeout.")
    except Exception as e:
        print(" CSP scan failed:", e)
    return tokens


#  Unified reader
def read_tokens():
    pkcs_tokens = read_pkcs11_tokens()
    if pkcs_tokens:
        print(" Tokens via PKCS#11:", pkcs_tokens)
    csp_tokens = read_csp_tokens()
    all_tokens = pkcs_tokens + [t for t in csp_tokens if t not in pkcs_tokens]
    return all_tokens


# Background monitor
def start_usb_monitor():
    def monitor():
        global last_detected_tokens
        print("\n USB monitor started...\n")

        WM_DEVICECHANGE = 0x0219
        DBT_DEVICEARRIVAL = 0x8000
        DBT_DEVICEREMOVECOMPLETE = 0x8004

        user32 = ctypes.windll.user32
        msg = wintypes.MSG()
        user32.CreateWindowExW(0, "STATIC", "USBWatcher", 0, 0, 0, 0, 0, 0, 0, 0, None)

        while True:
            if user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 1):
                if msg.message == WM_DEVICECHANGE and msg.wParam in [DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE]:
                    print("USB change detected — rescanning tokens...")
                    last_detected_tokens = read_tokens()
            time.sleep(1)

    threading.Thread(target=monitor, daemon=True).start()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/tokens", methods=["GET"])
def api_tokens():
    global last_detected_tokens
    if not last_detected_tokens or time.time() - last_scan_time > 10:
        last_detected_tokens = read_tokens()
    return jsonify({"tokens": last_detected_tokens, "message": " Tokens detected successfully."})


#  Certificates
@app.route("/api/certificates", methods=["POST"])
def list_certificates():
    try:
        data = request.get_json(force=True)
        dll_path = data.get("library")
        pin = data.get("pin")

        if not dll_path or not os.path.exists(dll_path):
            return jsonify({"error": "Invalid or missing DLL path"}), 400

        pk = lib(dll_path)
        slots = pk.get_slots(token_present=True)
        if not slots:
            return jsonify({"error": " No token slots found"}), 404

        slot = slots[0]
        certs = []

        #  Try slot.open(), then fallback to token.open()
        open_method = (
            getattr(slot, "open", None)
            or getattr(slot, "open_session", None)
            or getattr(slot, "openSession", None)
        )

        if open_method:
            print(" Using slot.open() style method")
        else:
            token = slot.get_token()
            open_method = getattr(token, "open", None)
            if open_method:
                print(" Using token.open() fallback method")
            else:
                return jsonify({
                    "error": "Slot and Token both missing open() method",
                    "slot_methods": dir(slot),
                    "token_methods": dir(token)
                }), 500

        # Open session and read certificates
        with open_method(user_pin=pin) as session:
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                try:
                    cert_data = bytes(obj[Attribute.VALUE])
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                    certs.append({
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial": hex(cert.serial_number),
                        "not_after": cert.not_valid_after.isoformat()
                    })
                except Exception as e:
                    print("Skipping invalid cert:", e)
                    continue

        if not certs:
            return jsonify({"error": " No certificates found or wrong PIN."}), 404

        print(" Certificates fetched successfully!")
        return jsonify({"certificates": certs}), 200

    except Exception as e:
        import traceback
        print(" Certificate listing error:", e)
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


if __name__ == "__main__":
    print(" Starting Token Utility Flask Server")
    print(f" Python Architecture: {platform.architecture()[0]}")
    start_usb_monitor()
    app.run(host="0.0.0.0", port=5000, debug=True)



# import os
# import json
# import time
# import subprocess
# import glob
# import ctypes
# import traceback
# import platform
# import logging
# from flask import Flask, jsonify, render_template, request
# from pkcs11 import lib, Attribute, ObjectClass
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend

# # -------------------- LOGGING --------------------
# BASE_DIR = os.path.dirname(__file__)
# LOG_DIR = os.path.join(BASE_DIR, "logs")
# os.makedirs(LOG_DIR, exist_ok=True)
# logging.basicConfig(
#     filename=os.path.join(LOG_DIR, "server.log"),
#     level=logging.INFO,
#     format="%(asctime)s %(levelname)s %(message)s"
# )

# app = Flask(__name__, template_folder="templates")

# # -------------------- HELPERS --------------------
# def find_pkcs11_libraries():
#     """Scan system paths for possible PKCS#11 DLLs."""
#     search_paths = [
#         r"C:\Windows\System32",
#         r"C:\Windows\SysWOW64",
#         r"C:\Program Files",
#         r"C:\Program Files (x86)"
#     ]
#     patterns = [
#         "*pkcs11*.dll",
#         "*eps2003*.dll",
#         "*wdp*.dll",
#         "*wdpkcs11*.dll",
#         "*idprime*.dll",
#         "*CryptoID*.dll",
#         "*token*.dll"
#     ]
#     found = []
#     for base in search_paths:
#         for pattern in patterns:
#             found.extend(glob.glob(os.path.join(base, "**", pattern), recursive=True))
#     return list(dict.fromkeys(found))


# def validate_libraries(lib_paths):
#     """Filter valid PKCS#11 DLLs."""
#     valid_64, valid_32 = [], []
#     for p in lib_paths:
#         try:
#             dll = ctypes.WinDLL(p)
#             if hasattr(dll, "C_GetFunctionList"):
#                 if "Program Files (x86)" in p or "SysWOW64" in p:
#                     valid_32.append(p)
#                 else:
#                     valid_64.append(p)
#         except Exception as e:
#             logging.warning(f"Skipping {p}: {e}")
#     return valid_64, valid_32


# def read_tokens_from_pkcs11(dll_paths):
#     tokens = []
#     for dll in dll_paths:
#         try:
#             pk = lib(dll)
#             slots = pk.get_slots(token_present=True)
#             for slot in slots:
#                 token = slot.get_token()
#                 label = str(token.label).strip() or "Unknown"
#                 serial = str(token.serial).strip() or "N/A"
#                 manufacturer = str(token.manufacturer_id).strip() or "Unknown"
#                 tokens.append({
#                     "label": label,
#                     "serial": serial,
#                     "manufacturer": manufacturer,
#                     "library": dll
#                 })
#         except Exception as e:
#             logging.error(f"Error reading {dll}: {e}")
#     return tokens


# # -------------------- FLASK ROUTES --------------------
# @app.route("/")
# def home():
#     return render_template("index.html")


# @app.route("/api/tokens", methods=["GET"])
# def api_tokens():
#     """Detect connected tokens."""
#     try:
#         libs = find_pkcs11_libraries()
#         valid_64, valid_32 = validate_libraries(libs)
#         tokens = read_tokens_from_pkcs11(valid_64)

#         if not tokens and valid_32:
#             python32 = os.getenv("PYTHON32_PATH", r"C:\Users\hp\AppData\Local\Programs\Python\Python315-32\python.exe")
#             if os.path.exists(python32):
#                 result = subprocess.run(
#                     [python32, "bridge32.py"],
#                     capture_output=True,
#                     text=True,
#                     timeout=15
#                 )
#                 if result.stdout:
#                     data = json.loads(result.stdout)
#                     tokens.extend(data.get("tokens", []))

#         if not tokens:
#             return jsonify({"tokens": [], "message": "⚠️ No tokens detected."})

#         return jsonify({"tokens": tokens, "message": "✅ Tokens detected successfully."})

#     except Exception as e:
#         logging.exception("Error detecting tokens")
#         return jsonify({"error": str(e)}), 500


# @app.route("/api/certificates", methods=["POST"])
# def list_certificates():
#     """List certificates from token."""
#     try:
#         data = request.get_json(force=True)
#         dll_path = data.get("library")
#         pin = data.get("pin", "")

#         if not dll_path or not os.path.exists(dll_path):
#             return jsonify({"error": "Invalid or missing DLL path"}), 400

#         pk = lib(dll_path)
#         slots = pk.get_slots(token_present=True)
#         if not slots:
#             return jsonify({"error": "No token slots found"}), 404

#         slot = slots[0]
#         certs = []

#         # ✅ Auto-handle both API styles
#         open_method = getattr(slot, "open", None) or getattr(slot, "open_session", None)
#         if not open_method:
#             return jsonify({"error": "Slot object missing session open method"}), 500

#         with open_method(user_pin=pin) as session:
#             for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
#                 try:
#                     cert_data = bytes(obj[Attribute.VALUE])
#                     cert = x509.load_der_x509_certificate(cert_data, default_backend())
#                     certs.append({
#                         "subject": cert.subject.rfc4514_string(),
#                         "issuer": cert.issuer.rfc4514_string(),
#                         "serial": hex(cert.serial_number),
#                         "not_after": cert.not_valid_after.isoformat()
#                     })
#                 except Exception as e:
#                     logging.warning(f"Invalid certificate skipped: {e}")
#                     continue

#         if not certs:
#             return jsonify({"error": "No certificates found or wrong PIN."}), 404

#         return jsonify({"certificates": certs}), 200

#     except Exception as e:
#         logging.exception("Certificate listing error")
#         return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# # -------------------- RUN SERVER --------------------
# if __name__ == "__main__":
#     logging.info(f"🚀 Starting TokenInfo Viewer Flask Server ({platform.architecture()[0]})")
#     app.run(host="0.0.0.0", port=5000, debug=True)
