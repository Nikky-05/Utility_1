from flask import Flask, request, jsonify, render_template, send_file
from pkcs11 import lib, Attribute, ObjectClass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ctypes, glob, os, io, zipfile

app = Flask(__name__, template_folder='templates')

# 🔍 Auto-detect PKCS#11 DLL
def auto_detect_pkcs11_lib():
    search_paths = [
        r"C:\Windows\System32",
        r"C:\Program Files",
        r"C:\Program Files (x86)"
    ]
    patterns = ["*mToken*.dll", "*ePass*.dll", "*pkcs11*.dll", "*token*.dll"]

    for base in search_paths:
        for pattern in patterns:
            for path in glob.glob(os.path.join(base, "**", pattern), recursive=True):
                try:
                    dll = ctypes.WinDLL(path)
                    if hasattr(dll, "C_GetFunctionList"):
                        print(f"Valid PKCS#11 library found: {path}")
                        return path
                except Exception:
                    continue
    print("No valid PKCS#11 DLL found.")
    return None


# 🏠 Serve HTML UI
@app.route("/")
def home():
    return render_template("index.html")


# 💳 List all connected tokens
@app.route("/api/tokens")
def list_tokens():
    dll_path = request.args.get("dll") or auto_detect_pkcs11_lib()
    if not dll_path or not os.path.exists(dll_path):
        return jsonify({"error": "PKCS#11 DLL not found"}), 400

    pkcs11 = lib(dll_path)
    tokens = []
    for slot in pkcs11.get_slots(token_present=True):
        try:
            t = slot.get_token()
            tokens.append({
                "label": getattr(t, "label", b"").decode("utf-8", errors="ignore"),
                "serial": getattr(t, "serial", b"").decode("utf-8", errors="ignore")
            })
        except Exception:
            continue
    return jsonify({"tokens": tokens})


# 🔐 Read certificates from token
@app.route("/api/read-certs", methods=["POST"])
def read_certs():
    data = request.get_json(force=True)
    dll_path = data.get("dll") or auto_detect_pkcs11_lib()
    pin = data.get("pin")
    token_label = data.get("tokenLabel")
    serial = data.get("serial")

    if not dll_path or not os.path.exists(dll_path):
        return jsonify({"error": f"PKCS#11 DLL not found: {dll_path}"}), 400
    if not pin:
        return jsonify({"error": "PIN not provided"}), 400


    pkcs11 = lib(dll_path)
    try:
        slots = pkcs11.get_slots(token_present=True)
        token = None
        for s in slots:
            try:
                t = s.get_token()
            except Exception:
                continue
            if serial and getattr(t, "serial", None) != serial:
                continue
            if token_label and getattr(t, "label", None) != token_label:
                continue
            token = t
            break
        if not token:
            return jsonify({"error": "No token found"}), 404

        certs = []
        with token.open(user_pin=pin) as session:
            for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                der = cert[Attribute.VALUE]
                cert_obj = x509.load_der_x509_certificate(bytes(der), default_backend())
                certs.append({
                    "subject": cert_obj.subject.rfc4514_string(),
                    "issuer": cert_obj.issuer.rfc4514_string(),
                    "serial": str(cert_obj.serial_number),
                })

        if not certs:
            return jsonify({"error": "No certificates found"}), 404
        return jsonify({"certs": certs})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 💾 Download all certificates as ZIP
@app.route("/api/download-all", methods=["POST"])
def download_all():
    data = request.json or {}
    dll = data.get("dll")
    pin = data.get("pin")

    if not dll or not os.path.exists(dll):
        dll = auto_detect_pkcs11_lib()
    if not dll or not os.path.exists(dll):
        return jsonify({"error": "PKCS#11 DLL not found"}), 400
    if not pin:
        return jsonify({"error": "PIN not provided"}), 400

    pkcs11 = lib(dll)
    slots = pkcs11.get_slots(token_present=True)
    if not slots:
        return jsonify({"error": "No tokens detected"}), 404

    token = slots[0].get_token()
    memory_zip = io.BytesIO()
    with zipfile.ZipFile(memory_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        with token.open(user_pin=pin) as session:
            count = 0
            for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                der = cert[Attribute.VALUE]
                cert_obj = x509.load_der_x509_certificate(bytes(der), default_backend())
                filename = f"{cert_obj.subject.rfc4514_string().replace(',', '_').replace('=', '-')}.cer"
                zf.writestr(filename, der)
                count += 1

    if memory_zip.getbuffer().nbytes == 0:
        return jsonify({"error": "No certificates found"}), 404

    memory_zip.seek(0)
    return send_file(
        memory_zip,
        as_attachment=True,
        download_name="certificates.zip",
        mimetype="application/zip"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
