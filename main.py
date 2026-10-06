from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from pydantic import BaseModel
import requests
import subprocess
import json
import tempfile
import os
import socket
from google import genai
from fpdf import FPDF

app = FastAPI(title="SecConsole Backend API")

# CORS Ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ANA SAYFA YÖNLENDİRMESİ (Not Found hatasını çözer)
@app.get("/")
def read_root():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "index.html dosyası bulunamadı."}

# Veri Modelleri
class CodeScanRequest(BaseModel):
    code: str
    language: str = "python"

class OsintRequest(BaseModel):
    domain: str

class VtRequest(BaseModel):
    resource: str
    api_key: str = ""

class AiFixRequest(BaseModel):
    code: str
    issues: list
    api_key: str = ""

class PdfExportRequest(BaseModel):
    issues: list
    code: str

# Türkçe Karakter Düzeltici (PDF İçin)
def tr_fix(text: str) -> str:
    mapping = {
        'ğ': 'g', 'Ğ': 'G',
        'ş': 's', 'Ş': 'S',
        'ı': 'i', 'İ': 'I',
        'ç': 'c', 'Ç': 'C',
        'ö': 'o', 'Ö': 'O',
        'ü': 'u', 'Ü': 'U'
    }
    for tr, en in mapping.items():
        text = text.replace(tr, en)
    return text

# 1. SAST KOD ANALİZİ (Bandit)
@app.post("/api/scan-code")
def scan_code(req: CodeScanRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Kod alanı boş olamaz.")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as tmp:
        tmp.write(req.code)
        tmp_path = tmp.name

    try:
        cmd = ["bandit", "-r", tmp_path, "-f", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        output = json.loads(result.stdout)
        results = output.get("results", [])
        
        parsed_issues = []
        for item in results:
            parsed_issues.append({
                "check_id": item.get("test_id"),
                "message": item.get("issue_text"),
                "severity": item.get("issue_severity"),
                "line": item.get("line_number")
            })

        return {"status": "success", "issues_count": len(parsed_issues), "issues": parsed_issues}

    except Exception as e:
        return {"status": "error", "message": f"Bandit analizi hatası: {str(e)}"}
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

# 2. VIRUSTOTAL ENTEGRASYONU
@app.post("/api/virustotal")
def scan_virustotal(req: VtRequest):
    api_key = req.api_key or os.environ.get("VT_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="Lütfen bir VirusTotal API Anahtarı sağlayın.")

    resource = req.resource.strip()
    headers = {"x-apikey": api_key}
    
    url = f"https://www.virustotal.com/api/v3/files/{resource}" if len(resource) in [32, 40, 64] else f"https://www.virustotal.com/api/v3/ip_addresses/{resource}"

    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            data = res.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0)
            }
        elif res.status_code == 404:
            return {"status": "warning", "message": "Virustotal veritabanında kayıt bulunamadı."}
        else:
            raise HTTPException(status_code=res.status_code, detail="VirusTotal sorgusu başarısız.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VT Bağlantı Hatası: {str(e)}")

# 3. AI OTO ONARIM (Gemini 2.5 Flash)
@app.post("/api/fix-code")
def fix_code_with_ai(req: AiFixRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Kod boş olamaz.")
    
    api_key = req.api_key or os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="Lütfen geçerli bir Gemini API Anahtarı sağlayın.")

    try:
        client = genai.Client(api_key=api_key)
        
        prompt = f"""
        Aşağıdaki Python kodunda tespit edilen güvenlik zafiyetleri (Bandit SAST):
        {json.dumps(req.issues, ensure_ascii=False, indent=2)}

        Orijinal Zafiyetli Kod:
        ```python
        {req.code}
        ```

        Görevlerin:
        1. Bu koddaki güvenlik zafiyetlerini düzelt (OWASP standartlarına uygun hale getir).
        2. Düzeltilmiş tam Python kodunu ver.
        3. Yapılan değişiklikleri kısaca Türkçe maddeler halinde açıkla.
        """

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )

        return {"status": "success", "explanation": response.text}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Düzeltme Hatası: {str(e)}")

# 4. PDF RAPOR OLUŞTURUCU
@app.post("/api/export-pdf")
def export_pdf_report(req: PdfExportRequest):
    try:
        pdf = FPDF()
        pdf.add_page()
        
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, tr_fix("SecConsole Guvenlik Tarama Raporu"), new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, tr_fix(f"Bulunan Toplam Zafiyet Sayisi: {len(req.issues)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        pdf.set_font("Helvetica", "", 10)
        for idx, issue in enumerate(req.issues, 1):
            severity = tr_fix(str(issue.get('severity', 'UNK')))
            check_id = tr_fix(str(issue.get('check_id', 'UNK')))
            line = issue.get('line', '?')
            msg = tr_fix(str(issue.get('message', '')))

            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"{idx}. [{severity}] {check_id} - Satir {line}", new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5, f"Detay: {msg}")
            pdf.ln(2)

        pdf_output = pdf.output()
        
        return Response(
            content=bytes(pdf_output), 
            media_type="application/pdf", 
            headers={"Content-Disposition": "attachment; filename=SecConsole_Security_Report.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Oluşturma Hatası: {str(e)}")

# 5. OSINT (Shodan InternetDB)
@app.post("/api/osint")
def osint_scan(req: OsintRequest):
    domain = req.domain.replace("https://", "").replace("http://", "").strip().split("/")[0]
    
    try:
        ip_address = socket.gethostbyname(domain)
        shodan_res = requests.get(f"https://internetdb.shodan.io/{ip_address}", timeout=5)
        
        if shodan_res.status_code == 200:
            data = shodan_res.json()
            return {
                "status": "success",
                "domain": domain,
                "ip": ip_address,
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", [])
            }
        else:
            return {"status": "warning", "domain": domain, "ip": ip_address, "ports": [], "hostnames": []}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sorgu hatası: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
