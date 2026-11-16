from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import zipfile, tempfile, re, hashlib, os
from datetime import datetime, timezone

app = FastAPI(title="PrivacyLens Analysis API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000","http://127.0.0.1:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

PERMISSIONS = {
 "android.permission.ACCESS_FINE_LOCATION": ("Precise location permission declared","High","Permissions"),
 "android.permission.ACCESS_COARSE_LOCATION": ("Approximate location permission declared","Medium","Permissions"),
 "android.permission.READ_CONTACTS": ("Contacts permission declared","High","Permissions"),
 "android.permission.RECORD_AUDIO": ("Microphone permission declared","High","Permissions"),
 "android.permission.CAMERA": ("Camera permission declared","Medium","Permissions"),
 "android.permission.READ_PHONE_STATE": ("Phone state permission declared","High","Permissions"),
 "android.permission.READ_EXTERNAL_STORAGE": ("External storage read permission declared","Medium","Permissions"),
 "android.permission.INTERNET": ("Network access permission declared","Low","Permissions"),
}
SDK_SIGNATURES = {
 "com.google.firebase.analytics":"Firebase Analytics",
 "io.sentry.android":"Sentry Android",
 "okhttp3":"OkHttp",
 "com.google.android.gms.maps":"Google Maps SDK",
 "com.facebook":"Meta SDK",
}
@app.get("/api/health")
def health():
    return {"status":"ok","service":"PrivacyLens Analysis API","timestamp":datetime.now(timezone.utc).isoformat()}

@app.post("/api/scan")
async def scan(file: UploadFile = File(...), include_sdk_inventory: bool = Form(True), compare_policy: bool = Form(True), extended_manifest_review: bool = Form(False)):
    name = Path(file.filename or "upload").name
    suffix = Path(name).suffix.lower()
    if suffix not in {".apk",".zip",".tar",".gz",".tgz"}:
        raise HTTPException(400,"Upload an APK or supported source archive (.zip, .tar, .gz, .tgz).")
    raw = await file.read()
    if len(raw) > 500 * 1024 * 1024:
        raise HTTPException(413,"File exceeds the 500 MB limit.")
    digest = hashlib.sha256(raw).hexdigest()
    evidence = []
    texts = []
    entries = []
    try:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/name
            path.write_bytes(raw)
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as z:
                    infos = z.infolist()
                    if len(infos) > 20000: raise HTTPException(400,"Archive contains too many entries.")
                    for info in infos:
                        if info.is_dir(): continue
                        entries.append(info.filename)
                        # Only read small text/XML files, never extract arbitrary paths.
                        if info.file_size <= 2_000_000 and (info.filename.endswith((".xml",".txt",".java",".kt",".gradle",".properties")) or info.filename.endswith("AndroidManifest.xml")):
                            try: texts.append(z.read(info).decode("utf-8",errors="ignore"))
                            except Exception: pass
            else:
                texts.append(raw[:2_000_000].decode("utf-8",errors="ignore"))
    except zipfile.BadZipFile:
        raise HTTPException(400,"The uploaded archive is damaged or is not a supported ZIP/APK.")
    corpus = "\n".join(texts)
    for permission,(title,severity,category) in PERMISSIONS.items():
        if permission in corpus:
            evidence.append({"id":"PL-"+str(1000+len(evidence)+1),"title":title,"severity":severity,"category":category,"evidence_type":"Confirmed declaration","confidence":100,"evidence":permission,"limitation":"A manifest declaration is not proof that the permission was granted or used at runtime."})
    sdk_found=[]
    if include_sdk_inventory:
        for sig,vendor in SDK_SIGNATURES.items():
            if sig in corpus or any(sig.replace(".","/") in e for e in entries):
                sdk_found.append({"vendor":vendor,"package_signature":sig,"evidence":"Package/class signature match","confidence":95})
    if "usesCleartextTraffic" in corpus and re.search(r'usesCleartextTraffic\s*=\s*"true"',corpus):
        evidence.append({"id":"PL-"+str(1000+len(evidence)+1),"title":"Cleartext traffic is enabled in manifest","severity":"High","category":"Configuration","evidence_type":"Confirmed declaration","confidence":100,"evidence":"usesCleartextTraffic=true","limitation":"Configuration evidence does not prove that sensitive traffic was transmitted."})
    # Source archive heuristic: a string match is explicitly labelled as a potential signal.
    for pattern,label in [(r'getDeviceId|getImei','Possible device identifier access path'),(r'getLastKnownLocation|requestLocationUpdates','Possible location API call path')]:
        if re.search(pattern,corpus):
            evidence.append({"id":"PL-"+str(1000+len(evidence)+1),"title":label,"severity":"Medium","category":"Data flow","evidence_type":"Potential risk","confidence":70,"evidence":"Static source text pattern match","limitation":"A code reference may be unreachable or unused; runtime validation is required."})
    return {
      "scan_id":digest[:12],"filename":name,"sha256":digest,"file_size":len(raw),
      "created_at":datetime.now(timezone.utc).isoformat(),"archive_entries":len(entries),
      "permissions_detected":sum(1 for f in evidence if f["category"]=="Permissions"),
      "sdk_inventory":sdk_found if include_sdk_inventory else [],
      "findings":evidence,
      "options":{"include_sdk_inventory":include_sdk_inventory,"compare_policy":compare_policy,"extended_manifest_review":extended_manifest_review},
      "analysis_scope":"Static archive inspection only. Binary Android manifest parsing and full DEX/source analysis may require additional tooling.",
      "limitations":["Static evidence does not establish runtime execution or actual collection.","No dynamic instrumentation or network traffic capture was performed.","Policy comparison requires policy text and human review."]
    }
