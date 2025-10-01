# gen_keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
open("rcpt_priv.pem","wb").write(priv.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))
open("rcpt_pub.pem","wb").write(priv.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
# lặp lại để tạo rcpt_priv.pem / rcpt_pub.pem
