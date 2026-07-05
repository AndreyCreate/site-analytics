#!/usr/bin/env python3
"""Encrypt index_src.html -> index.html (password-gated static page).

AES-256-GCM, key from PBKDF2-HMAC-SHA256 (600k iters). The published file
contains only ciphertext; decryption happens in-browser via WebCrypto.
Usage: python3 encrypt.py <password>
"""
import base64, os, sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
ITER = 600_000

def main():
    password = sys.argv[1].encode()
    src = sys.argv[2] if len(sys.argv) > 2 else "index_src.html"
    out_name = sys.argv[3] if len(sys.argv) > 3 else "index.html"
    plaintext = open(os.path.join(HERE, src), "rb").read()
    salt, nonce = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=ITER).derive(password)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    b64 = lambda b: base64.b64encode(b).decode()

    page = LOADER.replace("__SALT__", b64(salt)).replace("__NONCE__", b64(nonce)) \
                 .replace("__CT__", b64(ct)).replace("__ITER__", str(ITER))
    out = os.path.join(HERE, out_name)
    open(out, "w").write(page)
    print(f"written {out} ({len(page)//1024} KB)")

LOADER = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Create Today · доступ</title>
<style>
body{background:#F4F0E8;color:#0E0E0E;font-family:'Manrope',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#FFF;border:1px solid #E6E3DD;border-radius:20px;padding:36px 32px;max-width:360px;width:90%;box-shadow:0 8px 24px rgba(14,14,14,.08);text-align:center}
h1{font-family:'Times New Roman',serif;font-weight:400;font-size:26px;margin:0 0 6px}
p{color:#555;font-size:14px;margin:0 0 20px}
input{width:100%;padding:12px 14px;border:1px solid #D6D2C9;border-radius:10px;font-size:16px;box-sizing:border-box;outline:none;text-align:center;background:#F4F0E8}
input:focus{border-color:#E86F4D}
button{width:100%;margin-top:12px;padding:12px;border:none;border-radius:999px;background:#0E0E0E;color:#FFF;font-size:15px;font-weight:600;cursor:pointer}
button:hover{background:#E86F4D}
.err{color:#C24A2E;font-size:13px;margin-top:10px;min-height:18px}
</style>
</head>
<body>
<div class="box">
<h1>Create Today</h1>
<p>Финмодель — доступ по паролю</p>
<input id="pw" type="password" placeholder="Пароль" autofocus>
<button onclick="go()">Открыть</button>
<div class="err" id="err"></div>
</div>
<script>
const SALT="__SALT__",NONCE="__NONCE__",CT="__CT__",ITER=__ITER__;
const b=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function go(){
  const err=document.getElementById('err');err.textContent='';
  try{
    const pw=document.getElementById('pw').value;
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b(SALT),iterations:ITER,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
    const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b(NONCE)},key,b(CT));
    const html=new TextDecoder().decode(pt);
    document.open();document.write(html);document.close();
  }catch(e){err.textContent='Неверный пароль';}
}
document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')go()});
</script>
</body>
</html>"""

if __name__ == "__main__":
    main()
