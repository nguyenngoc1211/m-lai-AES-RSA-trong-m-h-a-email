#!/usr/bin/env python3
import os, io, json, base64, zipfile
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64e = lambda b: base64.b64encode(b).decode()

def ask(prompt, default=None, is_password=False):
    p = f"{prompt}" + (f" [{default}]" if default else "") + ": "
    s = getpass(p) if is_password else input(p)
    s = s.strip()
    return (default if s == "" and default is not None else s)

def yesno(prompt, default=False):
    d = "Y/n" if default else "y/N"
    s = input(f"{prompt} ({d}): ").strip().lower()
    if s == "": return default
    return s in ("y","yes")

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
            if os.path.isfile(p):
                z.write(p, arcname=os.path.basename(p))
            else:
                print(f"[bỏ qua] Không tìm thấy tệp đính kèm: {p}")
    return buf.getvalue()

def load_private_key_pem(path, password:bytes|None):
    return serialization.load_pem_private_key(open(path,"rb").read(), password=password)

def load_public_key_pem(path):
    return serialization.load_pem_public_key(open(path,"rb").read())

def main():
    print("=== Hybrid mail encrypt: AES-256-GCM + RSA-OAEP + RSA-PSS ===")
    sender_priv = ask("Đường dẫn khóa riêng người gửi (PEM)")
    sender_pass_str = ask("Mật khẩu cho khóa riêng người gửi (bỏ trống nếu không có)", is_password=True)
    sender_pass = sender_pass_str.encode() if sender_pass_str else None

    recipient_pub = ask("Đường dẫn khóa công khai người nhận (PEM)")
    subject = ask("Subject", default="No subject")

    if yesno("Nhập nội dung trực tiếp?", default=True):
        print("Nhập nội dung. Kết thúc bằng một dòng chỉ chứa: EOF")
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == "EOF":
                break
            lines.append(line)
        body = "\n".join(lines)
        body_file = None
    else:
        body_file = ask("Đường dẫn file nội dung (UTF-8)")
        body = None

    attach_raw = ask("Danh sách file đính kèm, cách nhau bởi dấu phẩy", default="")
    attachments = [p.strip() for p in attach_raw.split(",") if p.strip()]

    out_path = ask("Tên file đầu ra", default="envelope.json")

    payload = zip_payload(subject, body, body_file, attachments)

    aes_key = os.urandom(32)   # 256-bit
    nonce   = os.urandom(12)   # 96-bit
    ct      = AESGCM(aes_key).encrypt(nonce, payload, None)

    recip_pub = load_public_key_pem(recipient_pub)
    wrapped_key = recip_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    sender_priv_key = load_private_key_pem(sender_priv, sender_pass)
    signature = sender_priv_key.sign(
        nonce + ct,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    sender_pub_pem = sender_priv_key.public_key().public_bytes(
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
    with open(out_path,"w",encoding="utf-8") as f:
        json.dump(env,f,separators=(",",":"))
    print(f"Đã ghi {out_path}")

if __name__ == "__main__":
    main()
