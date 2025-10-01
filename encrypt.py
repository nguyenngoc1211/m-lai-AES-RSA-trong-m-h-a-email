#!/usr/bin/env python3
import argparse, os, io, json, base64, zipfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64e = lambda b: base64.b64encode(b).decode()
def zip_payload(subject:str, body:str|None, body_file:str|None, attachments:list[str])->bytes:
    msg = f"Subject: {subject}\n\n"
    if body_file:
        msg += open(body_file, "r", encoding="utf-8").read()
    else:
        msg += body or ""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("message.txt", msg)
        for p in attachments or []:
            z.write(p, arcname=os.path.basename(p))
    return buf.getvalue()

def load_private_key_pem(path, password:bytes|None):
    return serialization.load_pem_private_key(open(path,"rb").read(), password=password)

def load_public_key_pem(path):
    return serialization.load_pem_public_key(open(path,"rb").read())

def main():
    ap = argparse.ArgumentParser(description="Hybrid mail encrypt: AES-256-GCM + RSA-OAEP + RSA-PSS")
    ap.add_argument("--sender-priv", required=True, help="PEM private key of sender")
    ap.add_argument("--sender-pass", default=None, help="Password for sender private key (optional)")
    ap.add_argument("--recipient-pub", required=True, help="PEM public key of recipient")
    ap.add_argument("--subject", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--body", help="Plaintext body")
    g.add_argument("--body-file", help="Path to body text file (UTF-8)")
    ap.add_argument("--attach", nargs="*", default=[], help="Files to attach")
    ap.add_argument("--out", default="envelope.json")
    args = ap.parse_args()

    payload = zip_payload(args.subject, args.body, args.body_file, args.attach)

    aes_key = os.urandom(32)   # 256-bit
    nonce   = os.urandom(12)   # 96-bit
    ct      = AESGCM(aes_key).encrypt(nonce, payload, None)

    recip_pub = load_public_key_pem(args.recipient_pub)
    wrapped_key = recip_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    sender_priv = load_private_key_pem(args.sender_priv, args.sender_pass.encode() if args.sender_pass else None)
    signature = sender_priv.sign(
        nonce + ct,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    sender_pub_pem = sender_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    env = {
        "alg":"AES-256-GCM + RSA-OAEP(SHA-256) + RSA-PSS(SHA-256)",
        "nonce":b64e(nonce),
        "ciphertext":b64e(ct),
        "wrapped_key":b64e(wrapped_key),
        "signature":b64e(signature),
        "sender_pub":b64e(sender_pub_pem),
    }
    with open(args.out,"w",encoding="utf-8") as f: json.dump(env,f,separators=(",",":"))
    print(f"Written {args.out}")

if __name__ == "__main__":
    main()
