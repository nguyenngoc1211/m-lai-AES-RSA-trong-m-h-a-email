#!/usr/bin/env python3
import argparse, os, io, json, base64, zipfile, re
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64d = lambda s: base64.b64decode(s)

def load_private_key_pem(path, password:bytes|None):
    return serialization.load_pem_private_key(open(path,"rb").read(), password=password)

def unzip_payload(blob:bytes, outdir:str)->str:
    os.makedirs(outdir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob), "r") as z:
        z.extractall(outdir)
        msg = z.read("message.txt").decode("utf-8")
    open(os.path.join(outdir,"message.txt"),"w",encoding="utf-8").write(msg)
    return msg

def main():
    ap = argparse.ArgumentParser(description="Hybrid mail decrypt")
    ap.add_argument("--recipient-priv", required=True, help="PEM private key of recipient")
    ap.add_argument("--recipient-pass", default=None, help="Password for recipient private key (optional)")
    ap.add_argument("--in", dest="infile", required=True, help="envelope.json from sender")
    ap.add_argument("--out-dir", default="decrypted")
    args = ap.parse_args()

    env = json.load(open(args.infile, "r", encoding="utf-8"))
    nonce      = b64d(env["nonce"])
    ciphertext = b64d(env["ciphertext"])
    wrapped    = b64d(env["wrapped_key"])
    signature  = b64d(env["signature"])
    sender_pub = serialization.load_pem_public_key(b64d(env["sender_pub"]))

    recip_priv = load_private_key_pem(args.recipient_priv, args.recipient_pass.encode() if args.recipient_pass else None)
    aes_key = recip_priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    sender_pub.verify(
        signature,
        nonce + ciphertext,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    payload = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    msg = unzip_payload(payload, args.out_dir)

    m = re.search(r"^Subject:\s*(.*)$", msg, re.MULTILINE)
    print("OK. Output ->", args.out_dir)
    if m: print("Subject:", m.group(1))

if __name__ == "__main__":
    main()
