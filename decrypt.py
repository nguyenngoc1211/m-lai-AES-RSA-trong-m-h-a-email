#!/usr/bin/env python3
import os, io, json, base64, zipfile, re
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64d = lambda s: base64.b64decode(s)

def ask(prompt, default=None, is_password=False):
    p = f"{prompt}" + (f" [{default}]" if default else "") + ": "
    s = getpass(p) if is_password else input(p)
    s = s.strip()
    return (default if s == "" and default is not None else s)

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
    print("=== Hybrid mail decrypt ===")
    recipient_priv = ask("Đường dẫn khóa riêng người nhận (PEM)")
    recipient_pass_str = ask("Mật khẩu cho khóa riêng người nhận (bỏ trống nếu không có)", is_password=True)
    recipient_pass = recipient_pass_str.encode() if recipient_pass_str else None

    infile = ask("Đường dẫn envelope.json", default="envelope.json")
    out_dir = ask("Thư mục giải mã đầu ra", default="decrypted")

    env = json.load(open(infile, "r", encoding="utf-8"))
    nonce      = b64d(env["nonce"])
    ciphertext = b64d(env["ciphertext"])
    wrapped    = b64d(env["wrapped_key"])
    signature  = b64d(env["signature"])
    sender_pub = serialization.load_pem_public_key(b64d(env["sender_pub"]))

    recip_priv = load_private_key_pem(recipient_priv, recipient_pass)
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
    msg = unzip_payload(payload, out_dir)

    m = re.search(r"^Subject:\s*(.*)$", msg, re.MULTILINE)
    print("Giải mã OK →", out_dir)
    if m: print("Subject:", m.group(1))

if __name__ == "__main__":
    main()
