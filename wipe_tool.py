#!/usr/bin/env python3
"""
wipe_tool.py - Prototype secure wipe + certificate generator (Linux-first)
Usage:
    sudo python3 wipe_tool.py --device /dev/sdX --method auto --output ./outdir
Caveats:
 - For safety, default runs in "dry-run" mode unless --confirm provided.
 - Requires: Python3, pycryptodome, reportlab (for PDF), openssl (optional)
"""
from reportlab.pdfgen import canvas
import argparse
import json
import os
import subprocess
import sys
import time
import hashlib
from datetime import datetime
from base64 import b64encode
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# pip: pip install pycryptodome reportlab
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except Exception:
    print("Install reportlab: pip install reportlab")
    # continue; PDF generation will fail later

def run_cmd(cmd, capture=False):
    print("RUN:", " ".join(cmd))
    if capture:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    else:
        subprocess.check_call(cmd)

def detect_device_info(device):
    # Basic detection: size and model via lsblk and smartctl (if available)
    info = {"device": device}
    try:
        out = run_cmd(["lsblk", "-no", "NAME,SIZE,MODEL", device], capture=True)
        info["lsblk_line"] = out.strip()
    except Exception:
        info["lsblk_line"] = None
    return info

def perform_wipe(device, method, dry_run=True):
    log = {"device": device, "method": method, "start_time": datetime.utcnow().isoformat()+"Z", "steps":[]}
    # Methods: 'ata_secure_erase', 'nvme_format', 'overwrite_shred', 'zero'
    if method == "auto":
        # try NVMe -> ATA -> fallback shred
        # we will probe
        is_nvme = "/nvme" in device or "nvme" in device
        if is_nvme:
            chosen = "nvme_format"
        else:
            # attempt ATA
            chosen = "ata_secure_erase"
    else:
        chosen = method

    log["chosen_method"] = chosen

    if dry_run:
        log["steps"].append({"action":"dry_run","msg":"No destructive actions performed in dry-run mode."})
    else:
        if chosen == "nvme_format":
            # requires nvme-cli
            log["steps"].append({"action":"nvme_format","cmd":f"nvme format {device} -s 1 -f"})
            run_cmd(["nvme", "format", device, "-s", "1", "-f"])
        elif chosen == "ata_secure_erase":
            # use hdparm
            # Note: this is simplified — actual usage requires freezing/unfreezing, authentication, etc.
            log["steps"].append({"action":"ata_secure_erase","cmd":f"hdparm --security-erase NULL {device}"})
            run_cmd(["hdparm", "--security-erase", "NULL", device])
        elif chosen == "overwrite_shred":
            log["steps"].append({"action":"overwrite_shred","cmd":f"shred -v -n 3 {device}"})
            run_cmd(["shred","-v","-n","3",device])
        elif chosen == "zero":
            log["steps"].append({"action":"zero","cmd":f"dd if=/dev/zero of={device} bs=1M status=progress"})
            run_cmd(["dd","if=/dev/zero","of="+device,"bs=1M","status=progress"])
        else:
            raise ValueError("Unknown method")
    log["end_time"]=datetime.utcnow().isoformat()+"Z"
    return log

def hash_log(log):
    j = json.dumps(log, sort_keys=True).encode()
    return hashlib.sha256(j).hexdigest()

def sign_log_with_private_pem(log_json_bytes, private_pem_path):
    key = RSA.import_key(open(private_pem_path,"rb").read())
    h = SHA256.new(log_json_bytes)
    signature = pkcs1_15.new(key).sign(h)
    return b64encode(signature).decode()

def generate_certificate_json(log, signature_b64, signer="JNARDDC Prototype"):
    cert = {
        "wipe_log": log,
        "signature": signature_b64,
        "signer": signer,
        "public_key_fingerprint": hashlib.sha256(open("public.pem","rb").read()).hexdigest()
    }
    return cert

def generate_pdf_certificate(cert_json, pdf_path):
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, height-60, "Certificate of Secure Erasure")
    c.setFont("Helvetica", 10)
    c.drawString(40, height-90, f"Signer: {cert_json.get('signer')}")
    c.drawString(40, height-105, f"Generated: {datetime.utcnow().isoformat()}Z")
    c.drawString(40, height-130, f"Public key fingerprint (SHA256): {cert_json.get('public_key_fingerprint')}")
    # dump some log lines
    y = height-160
    c.setFont("Helvetica", 9)
    log = cert_json["wipe_log"]
    c.drawString(40, y, f"Device: {log.get('device')}")
    y -= 15
    c.drawString(40, y, f"Method: {log.get('chosen_method')}")
    y -= 15
    c.drawString(40, y, f"Start: {log.get('start_time')}")
    y -= 15
    c.drawString(40, y, f"End: {log.get('end_time')}")
    y -= 30
    c.drawString(40, y, "Signature (base64, truncated):")
    y -= 12
    sig = cert_json["signature"]
    # write signature in blocks
    for i in range(0, min(len(sig), 600), 80):
        c.drawString(40, y, sig[i:i+80])
        y -= 12
        if y < 80: break
    c.showPage()
    c.save()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", required=True, help="/dev/sdX or /dev/nvme0n1")
    parser.add_argument("--method", default="auto", choices=["auto","nvme_format","ata_secure_erase","overwrite_shred","zero"])
    parser.add_argument("--out", default="./out", help="output directory")
    parser.add_argument("--private-key", default="private.pem", help="private key to sign")
    parser.add_argument("--dry-run", action="store_true", help="do not perform destructive actions")
    parser.add_argument("--confirm", action="store_true", help="by default do dry-run; use --confirm to allow destructive operations")
    args = parser.parse_args()

    if args.dry_run and args.confirm:
        print("Both dry-run and confirm set; proceeding as dry-run.")
    do_destroy = args.confirm and not args.dry_run

    os.makedirs(args.out, exist_ok=True)

    device_info = detect_device_info(args.device)
    log = perform_wipe(args.device, args.method, dry_run=(not do_destroy))

    # add device detection info
    log["device_info"] = device_info
    log_bytes = json.dumps(log, sort_keys=True, indent=2).encode()

    # compute hash
    log_hash = hash_log(log)
    log["sha256"] = log_hash

    # sign
    signature_b64 = sign_log_with_private_pem(json.dumps(log, sort_keys=True).encode(), args.private_key)

    cert = generate_certificate_json(log, signature_b64)
    # write outputs
    json_path = os.path.join(args.out, f"wipe_certificate_{int(time.time())}.json")
    with open(json_path,"w") as f:
        json.dump(cert, f, indent=2)
    print("Wrote JSON certificate:", json_path)

    # PDF
    pdf_path = os.path.join(args.out, f"wipe_certificate_{int(time.time())}.pdf")
    try:
        generate_pdf_certificate(cert, pdf_path)
        print("Wrote PDF certificate:", pdf_path)
    except Exception as e:
        print("PDF generation failed:", e)

    print("Done. Public key fingerprint:", cert["public_key_fingerprint"])

if __name__ == "__main__":
    main()
