#!/usr/bin/env python3
import json, sys, base64, hashlib
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

if len(sys.argv) < 2:
    print("Usage: verify_cert.py certificate.json")
    sys.exit(1)

cert_path = sys.argv[1]
cert = json.load(open(cert_path))
sig = base64.b64decode(cert["signature"])
log = cert["wipe_log"]
log_bytes = json.dumps(log, sort_keys=True).encode()

# compute fingerprint check
pub_bytes = open("public.pem","rb").read()
fingerprint = hashlib.sha256(pub_bytes).hexdigest()
if fingerprint != cert.get("public_key_fingerprint"):
    print("Warning: public key fingerprint mismatch!")

pub = RSA.import_key(pub_bytes)
h = SHA256.new(log_bytes)
try:
    pkcs1_15.new(pub).verify(h, sig)
    print("Signature: VALID")
    print("Wipe log summary:")
    print(" Device:", log.get("device"))
    print(" Method:", log.get("chosen_method"))
    print(" Start:", log.get("start_time"))
    print(" End:", log.get("end_time"))
    print(" SHA256(log):", log.get("sha256"))
except Exception as e:
    print("Signature verification failed:", e)
