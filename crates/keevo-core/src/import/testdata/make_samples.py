# 生成导入测试用的样例：有密码保护的 Bitwarden 导出（PBKDF2，AES 用 openssl 命令行，独立于 Rust 实现）与 1PUX。
import base64, hashlib, hmac, json, subprocess, sys, zipfile

out = sys.argv[1]
password, salt, iters = "correct horse battery", "6gQ6yPUQ3l0yCgIL7yGO8g==", 5000
key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iters, 32)
enc = hmac.new(key, b"enc\x01", hashlib.sha256).digest()   # HKDF-Expand，长度 32 只需一块
mac = hmac.new(key, b"mac\x01", hashlib.sha256).digest()

def encrypt(plain: bytes, iv: bytes) -> str:
    ct = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-K", enc.hex(), "-iv", iv.hex()],
                        input=plain, capture_output=True, check=True).stdout
    tag = hmac.new(mac, iv + ct, hashlib.sha256).digest()
    return "2." + "|".join(base64.b64encode(x).decode() for x in (iv, ct, tag))

plain = open(f"{out}/bitwarden.json", "rb").read()
doc = {"encrypted": True, "passwordProtected": True, "salt": salt, "kdfType": 0, "kdfIterations": iters,
       "kdfMemory": None, "kdfParallelism": None,
       "encKeyValidation_DO_NOT_EDIT": encrypt(b"a1b2c3d4-0000-4000-8000-000000000000", bytes(range(16))),
       "data": encrypt(plain, bytes(range(16, 32)))}
open(f"{out}/bitwarden-encrypted.json", "w").write(json.dumps(doc, indent=2) + "\n")

item = lambda cat, title, details, **kw: {"uuid": title.lower().replace(" ", "-"), "favIndex": kw.get("fav", 0),
    "createdAt": 1700000000, "updatedAt": 1700000000, "state": kw.get("state", "active"), "categoryUuid": cat,
    "details": details, "overview": {"title": title, "url": kw.get("url", ""), "urls": kw.get("urls", []),
    "tags": kw.get("tags", []), "subtitle": "", "ps": 0, "pbe": 0.0, "pgrng": False}}
items = [
    item("001", "GitHub", {"loginFields": [
            {"value": "octocat", "name": "login", "fieldType": "T", "designation": "username"},
            {"value": "Tr0ub4dor&3-horse", "name": "password", "fieldType": "P", "designation": "password"},
            {"value": "✓", "name": "remember", "fieldType": "C"}],
         "notesPlain": "work account",
         "sections": [{"title": "", "name": "add more", "fields": [
            {"title": "one-time password", "id": "TOTP_1", "value": {"totp": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"}},
            {"title": "recovery email", "id": "e1", "value": {"email": {"email_address": "oct@example.com", "provider": None}}}]},
            {"title": "Security", "name": "sec", "fields": [
            {"title": "PIN", "id": "p1", "value": {"concealed": "2468"}},
            {"title": "since", "id": "d1", "value": {"date": 1700000000}}]}],
         "passwordHistory": []},
         fav=1, url="https://github.com", urls=[{"label": "", "url": "https://github.com"}, {"label": "gist", "url": "https://gist.github.com"}], tags=["work", "dev"]),
    item("002", "Visa", {"sections": [{"title": "", "name": "", "fields": [
            {"title": "cardholder name", "id": "cardholder", "value": {"string": "Jane Doe"}},
            {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
            {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202903}},
            {"title": "verification number", "id": "cvv", "value": {"concealed": "123"}}]}]}),
    item("003", "Wi-Fi", {"notesPlain": "SSID: Keevo-Home"}),
    item("102", "Prod DB", {"sections": [{"title": "", "name": "", "fields": [
            {"title": "type", "id": "database_type", "value": {"menu": "postgresql"}},
            {"title": "server", "id": "hostname", "value": {"string": "db.internal"}},
            {"title": "port", "id": "port", "value": {"string": "5432"}},
            {"title": "username", "id": "username", "value": {"string": "app"}},
            {"title": "password", "id": "password", "value": {"concealed": "pg-pass"}}]}]}),
    item("114", "Deploy key", {"sections": [{"title": "", "name": "", "fields": [
            {"title": "private key", "id": "private_key", "value": {"sshKey": {"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
             "metadata": {"publicKey": "ssh-ed25519 AAAAC3Nza deploy", "fingerprint": "SHA256:abc", "keyType": "ed25519"}}}}]}]}),
    item("006", "Passport scan", {"documentAttributes": {"fileName": "passport.pdf", "documentId": "doc1", "decryptedSize": 1024}}),
    item("001", "Old forum", {"loginFields": [{"value": "me", "name": "u", "fieldType": "T", "designation": "username"},
            {"value": "p@ssw0rd", "name": "p", "fieldType": "P", "designation": "password"}]}, state="archived", url="http://forum.example.com"),
]
data = {"accounts": [{"attrs": {"accountName": "Sample", "name": "Sample", "email": "sample@example.com", "uuid": "A1", "domain": "my.1password.com"},
         "vaults": [{"attrs": {"uuid": "V1", "desc": "", "avatar": "", "name": "Private", "type": "P"}, "items": items}]}]}
with zipfile.ZipFile(f"{out}/sample.1pux", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("export.attributes", json.dumps({"version": 3, "description": "1Password Unencrypted Export", "createdAt": 1700000000}))
    z.writestr("export.data", json.dumps(data, ensure_ascii=False))
    z.writestr("files/doc1__passport.pdf", b"%PDF-1.4 sample")
