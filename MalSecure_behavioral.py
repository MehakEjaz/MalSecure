import os
import sys
import argparse
import numpy as np
import lightgbm as lgb
import thrember
import pickle
import json
import time
import re as _re
import hashlib
import requests
from pathlib import Path
def get_vt_threat_label(sha256: str) -> str:
    """Quick VT lookup — returns threat label string or empty string."""
    try:
        key_file = Path.home() / "sc0pe_Base" / "sc0pe_VT_apikey.txt"
        if not key_file.exists():
            return ""
        api_key = key_file.read_text(encoding="utf-8").splitlines()[0].strip()
        if not api_key:
            return ""
        
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if not resp.ok:
            return ""
        
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        threat_class = attrs.get("popular_threat_classification", {})
        return str(threat_class.get("suggested_threat_label") or "").strip()
    except Exception:
        return ""

# ============================================================
# 1️⃣ CONFIGURATION & DYNAMIC MAPPING
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(SCRIPT_DIR, "ml_analysis", "models")

# Mapping your actual filenames from the screenshot
MODEL_MAP = {
    "PE": "EMBER2024_PE.model",
    "Win32": "EMBER2024_Win32.model",
    "Win64": "EMBER2024_Win64.model",
    "DotNet": "EMBER2024_Dot_Net.model",
    "ELF": "EMBER2024_ELF.model",
    "APK": "EMBER2024_APK.model",
    "PDF": "EMBER2024_PDF.model",
    "PACKER": "EMBER2024_packer.model",
    "FAMILY": "EMBER2024_family.model",
    "BEHAVIOR": "EMBER2024_behavior.model",
    "EXPLOIT": "EMBER2024_exploit.model"
}
import hashlib

def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
# ============================================================
# 2️⃣ SAFE LOADING WRAPPER (The "Anti-Crash" Fix)
# ============================================================
def safe_predict(model_key, data_vector, h_notes):
    model_name = MODEL_MAP.get(model_key)
    if not model_name: return 0.0
        
    path = os.path.join(MODEL_DIR, model_name)
    if not os.path.exists(path): return 0.0

    try:
        with open(path, "rb") as f:
            header = f.read(4)
            f.seek(0)
            
            # 1. Handle Pickled Ensembles (The 32-Booster Lists)
            if header.startswith(b"\x80"):
                obj = pickle.load(f)
                
                if isinstance(obj, list):
                    # It's an ensemble! Average the scores of all boosters
                    scores = []
                    for item in obj:
                        if hasattr(item, 'predict'):
                            res = item.predict(data_vector)
                            scores.append(float(res[0]))
                    
                    if not scores: return 0.0
                    return sum(scores) / len(scores) # The Committee Average
                else:
                    model = obj
            
            # 2. Handle Standard Models
            else:
                model = lgb.Booster(model_file=path)
        
        prediction = model.predict(data_vector)
        return float(prediction[0]) if not isinstance(prediction[0], (list, np.ndarray)) else prediction[0]
        
    except Exception as e:
        # Don't let a minor error stop the whole scan
        return 0.0

# ============================================================
# 3️⃣ ENHANCED FILE INSPECTION
# ============================================================
def get_detailed_type(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read(4096)
            if data.startswith(b"MZ"):
                if b"BSJB" in data: return "DotNet"
                pe_off = int.from_bytes(data[0x3C:0x40], "little")
                machine = data[pe_off+4:pe_off+6]
                if machine == b"\x4c\x01": return "Win32"
                if machine == b"\x64\x86": return "Win64"
                return "PE"
            if data.startswith(b"\x7fELF"): return "ELF"
            if data.startswith(b"%PDF"): return "PDF"
            if data[:2] == b"PK": return "APK"
    except: pass
    return "UNKNOWN"
import subprocess

def get_signature_info(filepath):
    """Verifies signature and returns (is_valid, signer_name)."""
    try:
        # Requesting Status and Signer Subject from PowerShell
        cmd = f'Get-AuthenticodeSignature "{filepath}" | Select-Object Status, @{{Name="Signer";Expression={{$_.SignerCertificate.Subject}}}} | ConvertTo-Json'
        output = subprocess.check_output(['powershell', '-Command', cmd], shell=True).decode().strip()
        
        import json
        data = json.loads(output)
        
        # Status 0 is 'Valid'
        is_valid = data.get("Status") == 0
        signer = data.get("Signer", "")
        
        return is_valid, signer
    except:
        return False, ""

def run_heuristics(filepath, ml_score):
    risk_adj = 0
    notes = []
    clean_path = filepath.lower()
    base_name = os.path.basename(clean_path)

    # System & Troubleshooting (Sysinternals & standard tools)
    ADMIN_TOOLS = [
        "sysmon.exe", "sysmon64.exe", "procmon.exe", "procexp.exe", 
        "autoruns.exe", "tcpview.exe", "procdump.exe", "accesschk.exe",
        "handle.exe", "vmmap.exe", "rammap.exe", "whois.exe"
    ]

    # Security & Network Analysis
    NET_TOOLS = [
        "wireshark.exe", "tshark.exe", "nmap.exe", "winpcap.exe", 
        "npcap.exe", "putty.exe", "winscp.exe", "filezilla.exe",
        "zenmap.exe", "advanced_ip_scanner.exe"
    ]

    # Developer & Compilation Tools (AI often flags these as "droppers")
    DEV_TOOLS = [
        "git.exe", "python.exe", "node.exe", "code.exe", "powershell_ise.exe",
        "gcc.exe", "make.exe", "docker.exe", "kubectl.exe", "vstest.console.exe",
        "msbuild.exe", "devenv.exe", "javac.exe"
    ]

    # Benchmarking & Hardware (Often use low-level drivers that look like rootkits)
    HW_TOOLS = [
        "cpuz.exe", "gpuz.exe", "hwinfo64.exe", "coretemp.exe", 
        "perfmon.exe", "resmon.exe"
    ]
    
    GOLDEN_TOOLS = ADMIN_TOOLS + NET_TOOLS + DEV_TOOLS + HW_TOOLS

    # 2. EXTENDED TRUSTED ZONES
    TRUSTED_ZONES = [
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\windows\\winsxs",
        "c:\\windows\\microsoft.net", # For .NET framework binaries
        "c:\\programdata"            # Common for shared app resources
    ]
    TRUSTED_PUBLISHERS = [
        "Microsoft", "Google", "Mozilla", "Intel", "Cisco", 
        "Apple", "NVIDIA", "Advanced Micro Devices", "Oracle"
    ]

    # 2. Get detailed signature info
    is_signed, signer_name = get_signature_info(filepath)

    # 3. Check for "Golden Tool" Trust
    is_golden_match = any(tool.lower() in base_name.lower() for tool in GOLDEN_TOOLS)
    if is_golden_match and is_signed:
        risk_adj -= 95 
        notes.append(f"[-] Identified Known Admin Tool: {base_name} (Global Trust Applied)")
        return risk_adj, notes, False

    # 4. NEW: Check for Publisher Trust
    # This catches legitimate software not in your specific tool lists
    if is_signed and any(pub.lower() in signer_name.lower() for pub in TRUSTED_PUBLISHERS):
        risk_adj -= 85
        notes.append(f"[-] Verified Trusted Publisher: {signer_name}")
        return risk_adj, notes, False

    # 5. Existing System Zone Logic
    
    in_system_zone = any(zone in clean_path for zone in TRUSTED_ZONES)

    if in_system_zone:
        if is_signed:
            risk_adj -= 80 
            notes.append(f"[-] Verified {signer_name} Signature in System Path")
        else:
            risk_adj += 25 # Increased penalty for unsigned in system folders
            notes.append("[!] CRITICAL: Unsigned binary in System Folder!")

    # 4. EICAR String Search
    try:
        with open(filepath, "r", errors="ignore") as f:
            if "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" in f.read():
                risk_adj += 100
                notes.append("[!!!] EICAR SIGNATURE DETECTED")
    except: pass

    return risk_adj, notes, in_system_zone
# ============================================================
# 4️⃣ ANALYSIS ENGINE
# ============================================================
def analyze_binary(sample_path, json_out=False):
    sample_path = os.path.abspath(sample_path) 
    f_type = get_detailed_type(sample_path)
    base_name = os.path.basename(sample_path)
    file_hash = get_sha256(sample_path)
    h_notes = []

    # 1. Feature Extraction
    try:
        extractor = thrember.PEFeatureExtractor()
        with open(sample_path, "rb") as f:
            byte_array = np.frombuffer(f.read(), dtype=np.uint8)
        X = np.expand_dims(extractor.feature_vector(byte_array), axis=0)
    except Exception as e:
        print(f"[-] Extraction Error: {e}")
        return

    # 2. Multi-Model Pipeline
    ml_conf = safe_predict(f_type, X, h_notes)
    if ml_conf == 0.0 and f_type != "UNKNOWN":
        ml_conf = safe_predict("PE", X, h_notes)

    # Secondary Model Insights
    packer_score = safe_predict("PACKER", X, h_notes)
    behavior_score = safe_predict("BEHAVIOR", X, h_notes)
    
    family_info = "N/A"
    if ml_conf > 0.6:
        fam_results = safe_predict("FAMILY", X, h_notes)
        if isinstance(fam_results, (list, np.ndarray)):
            family_info = f"Cluster_{np.argmax(fam_results)}"

    # ============================================================
    # 3️⃣ SOC WEIGHTED SCORE FUSION (Nuanced Version)
    # ============================================================
    base_score = ml_conf * 100
    
    # Force Multipliers (Aggression)
    multiplier = 1.0
    if behavior_score > 0.5: multiplier += 0.25
    if packer_score > 0.7: multiplier += 0.35
    
    # Calculate Initial Weighted Risk
    weighted_risk = base_score * multiplier
    
    # Apply Heuristic Adjustments
    h_adj, h_findings, in_system_zone = run_heuristics(sample_path, ml_conf)
    h_notes.extend(h_findings)

    # 🛡️ THE PRECISION RISK ENGINE (SOC Optimized)
    
    # Check for specific findings from run_heuristics
    is_signed = "Verified Microsoft Signature" in str(h_findings)
    is_golden = "Global Trust" in str(h_findings)
    is_critical = "[!] CRITICAL" in str(h_findings)

    # Stage 1: THE "GOLDEN" ANCHOR (Known Admin Tools like Sysmon)
    if is_signed and is_golden:
        # We trust the identity 98%. Even if ML is 1.0, score is 2.0.
        final_risk = weighted_risk * 0.02 
        
    # Stage 2: THE "MICROSOFT" ANCHOR (Signed Windows Components)
    elif is_signed and in_system_zone:
        # High confidence it's a real system file. Cap risk at 'Low'.
        final_risk = min(weighted_risk * 0.10, 15.0) 

    # Stage 3: THE "SUSPICION" WEIGHT (Unsigned in System Path)
    elif is_critical:
        # 60% ML weight + 40% Location Penalty. 
        # A clean ML file (0.1) won't hit Malicious, but a dirty one (0.8) will.
        ml_impact = weighted_risk * 0.6
        location_penalty = 25.0 
        final_risk = ml_impact + location_penalty
        
        # Add a "Packer Penalty" if it's unsigned and packed
        if packer_score > 0.8: final_risk += 15
        
    # Stage 4: DEFAULT (User Folders, Unsigned Apps)
    else:
        final_risk = weighted_risk + h_adj

    # Final Boundary Check
    final_risk = max(0, min(100, final_risk))
    # ── VT threat label enrichment ──
    vt_label = get_vt_threat_label(file_hash)

    # This part MUST be outside the 'if not json_out' block
    clean_name = _re.sub(r'^[0-9a-f]{8,10}_', '', base_name, flags=_re.IGNORECASE)
    report_data = {
        "filename": clean_name,
        "target_type": f_type,
        "sha256": file_hash,
        "ml_conf": ml_conf,
        "behavior_score": behavior_score,
        "packer_score": packer_score,
        "final_risk": final_risk,
        "family": family_info,
        "notes": h_notes,
        "vt_threat_label": vt_label,   # ← NEW: flat field for easy access
    }

    # ============================================================
    # 4️⃣ FINAL REPORT GENERATION (Wrapped for JSON Safety)
    # ============================================================
    if not json_out:  # <--- Add this wrapper
        if final_risk > 75:
            status, color = "MALICIOUS", "\033[91m"
        elif final_risk > 45:
            status, color = "SUSPICIOUS", "\033[93m"
        elif final_risk > 15:
            status, color = "LOW RISK", "\033[94m"
        else:
            status, color = "TRUSTED", "\033[92m"

        print("\n" + "═"*65)
        print(f"  MalSecure EMBER 2024 | SOC ANALYSIS: {base_name}")
        print("═"*65)
        print(f" Target Type    : {f_type}")
        print(f" Detection Base : {ml_conf:.4f}")
        print(f" Behavior Score : {behavior_score:.4f}")
        print(f" Packer/Obfusc. : {packer_score:.4f}")
        print(f" Family Group   : {family_info}")
        print(f" SHA-256        : {file_hash}")
        print(f" Final Risk     : {color}{final_risk:.2f}/100 ({status})\033[0m")
        print("─"*65)
        if h_notes:
            for n in sorted(set(h_notes)): print(f" > {n}")
        print("═"*65 + "\n")

    # This part MUST be outside the 'if not json_out' block so the data is returned
    clean_name = _re.sub(r'^[0-9a-f]{8,10}_', '', base_name, flags=_re.IGNORECASE)
    report_data = {
      "filename": clean_name,
      "target_type": f_type,      # <--- Add this line to capture the result of get_detailed_type
      "sha256": file_hash,
      "ml_conf": ml_conf,
      "behavior_score": behavior_score, # Optional: include this if missing from UI
      "packer_score": packer_score,
      "final_risk": final_risk,
      "family": family_info,
      "notes": h_notes
    }

    if json_out:
        return report_data  

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    # Catching the True/False passed from Malsecure.py
    parser.add_argument("report_mode", nargs='?', default="False") 
    
    args = parser.parse_args()
    
    # Logic to check if we are in JSON/Report mode
    use_json = args.json or (args.report_mode.lower() == "true")

    if os.path.exists(args.file):
        result = analyze_binary(args.file, json_out=use_json)
        
        if use_json:
            # 1. Generate timestamped filename to match other modules
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            report_name = f"sc0pe_behavior_report_{timestamp}.json"

            try:
                # 2. Save the report to a file for the UI
                with open(report_name, "w") as f:
                    json.dump(result, f, indent=4)
            except Exception as e:
                # Avoid printing errors to stdout if the UI is expecting clean JSON
                if not use_json:
                    print(f"[-] Failed to save report: {e}")

            # 3. Print the JSON to stdout so the UI can capture it in real-time
            print(json.dumps(result))