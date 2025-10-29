from flask import Flask, jsonify, render_template, request
from pkcs11 import lib, Attribute, ObjectClass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ctypes, os, platform, subprocess, json, glob, threading, time
from ctypes import wintypes
from werkzeug.utils import secure_filename
import tempfile
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7


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


def find_pkcs11_libraries():
    """
    Optimized DLL scanner — avoids deep recursion.
    Scans only top-level known vendor folders for speed (~1–2s).
    """
    search_paths = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files (x86)\eMudhra",
        r"C:\Program Files (x86)\CryptoID",
        r"C:\Program Files",
    ]

    patterns = [
        "*pkcs11*.dll",
        "*eps2003*.dll",
        "*CryptoID*.dll",
        "*token*.dll",
        "*IDPrime*.dll",
        "*wdpkcs11*.dll",
    ]

    found = []
    for base in search_paths:
        for pattern in patterns:
            # ⚡ no recursion, only one level deep
            found += glob.glob(os.path.join(base, pattern))
            found += glob.glob(os.path.join(base, "*", pattern))
    return list(dict.fromkeys(found))


def detect_libraries():
    """
    Detect valid PKCS#11 libraries faster — 
    uses pre-known vendor paths and quick validation.
    """
    print(f"\n⚡ Fast scanning PKCS#11 libraries for {platform.architecture()[0]} Python...\n")

    # ⚡ Direct known libraries first
    common_libs = [
        r"C:\Program Files (x86)\CryptoID\CryptoIDA_pkcs11.dll",
        r"C:\Windows\System32\eTPKCS11.dll",
        r"C:\Windows\System32\eps2003csp11.dll",
        r"C:\Windows\System32\wdpkcs11.dll",
        r"C:\Windows\System32\SafeNetPKCS11.dll",
    ]

    all_libs = [dll for dll in common_libs if os.path.exists(dll)]
    # Add extra from quick find
    all_libs += find_pkcs11_libraries()

    valid_libs, bit32_libs = [], []
    for dll_path in set(all_libs):
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
        return valid_libs or [], bit32_libs
    else:
        return bit32_libs or [], valid_libs


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


def read_tokens():
    """
    Fast token detection with caching and async deep scan fallback.
    """
    global last_detected_tokens, last_scan_time

    #  Cache results for 15 s
    if last_detected_tokens and time.time() - last_scan_time < 15:
        return last_detected_tokens

    start_time = time.time()
    pkcs_tokens = read_pkcs11_tokens()
    if pkcs_tokens:
        print(f" Tokens via PKCS#11: {pkcs_tokens}")
    else:
        print("No tokens via PKCS#11. Trying CSP...")
    csp_tokens = read_csp_tokens()
    all_tokens = pkcs_tokens + [t for t in csp_tokens if t not in pkcs_tokens]

    #  Background deep scan if empty
    if not all_tokens:
        def deep_scan_job():
            global last_detected_tokens
            print(" Starting background deep scan for tokens...")
            tokens = read_pkcs11_tokens()
            if tokens:
                last_detected_tokens = tokens
                print(" Deep scan found:", tokens)
        threading.Thread(target=deep_scan_job, daemon=True).start()

    last_detected_tokens = all_tokens
    last_scan_time = time.time()

    print(f" Token detection finished in {round(time.time() - start_time, 2)} s")
    return all_tokens


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


# this code pdf sign

@app.route("/api/sign", methods=["POST"])
def sign_pdf():
    try:
        # Get uploaded file and parameters
        pdf_file = request.files.get("pdf")
        cert_serial = request.form.get("cert_serial")
        library = request.form.get("library")
        pin = request.form.get("pin")

        if not pdf_file or not cert_serial or not library:
            return jsonify({"error": "Missing required fields"}), 400

        # Save uploaded PDF temporarily
        temp_dir = tempfile.mkdtemp()
        pdf_path = os.path.join(temp_dir, secure_filename(pdf_file.filename))
        pdf_file.save(pdf_path)

        # Load PKCS#11 library
        pk = lib(library)
        slots = pk.get_slots(token_present=True)
        if not slots:
            return jsonify({"error": "No tokens available"}), 404

        slot = slots[0]
        with slot.open(user_pin=pin) as session:
            cert_obj = None
            priv_key = None

            # Find cert and matching private key
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                cert_data = bytes(obj[Attribute.VALUE])
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                if hex(cert.serial_number) == cert_serial:
                    cert_obj = cert
                    break

            if not cert_obj:
                return jsonify({"error": "Certificate not found in token"}), 404

            for obj in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}):
                priv_key = obj
                break

            if not priv_key:
                return jsonify({"error": "Private key not found"}), 404

            # Create CMS/PKCS7 signature
            with open(pdf_path, "rb") as f:
                data = f.read()

            signer = pkcs7.PKCS7SignatureBuilder().set_data(data)
            signer = signer.add_signer(
                cert_obj,
                cert_obj.public_key(),
                hashes.SHA256()
            )
            signature = signer.sign(Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])

            # Save signature to file
            sig_path = pdf_path.replace(".pdf", "_signed.p7s")
            with open(sig_path, "wb") as f:
                f.write(signature)

        print(f" PDF signed: {sig_path}")
        return jsonify({
            "message": "PDF signed successfully!",
            "signature_path": sig_path
        }), 200

    except Exception as e:
        import traceback
        print("PDF sign error:", e)
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


if __name__ == "__main__":
    print(" Starting Token Utility Flask Server")
    print(f" Python Architecture: {platform.architecture()[0]}")
    # start_usb_monitor()
    app.run(host="0.0.0.0", port=5000, debug=True)
