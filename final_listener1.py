import joblib
import socket
import pandas as pd
from scapy.all import sniff, DNS, DNSQR, IP, TCP, Raw
from scapy.layers.http import HTTPRequest
from datetime import datetime
from math import log2
import re
import requests

# --- 1. CONFIGURATION ---

# Load trained model (ensure this path is correct)
try:
    model_path = "C:\\Users\\anees\\Downloads\\OBJECT DETECTION\\dns_spoof_detector\\data\\model\\final_model\\1dns_binary_rf_model_optimized.joblib"
    model = joblib.load(model_path)
    print("✅ Listener: AI Model loaded successfully.")
except Exception as e:
    print(f"❌ Listener ERROR: Could not load model. Exiting. Error: {e}")
    exit()

# Hardcoded rules & Features
BENIGN_DOMAINS = {"google.com", "chatgpt.com", "wikipedia.com", "openai.com"}
MALICIOUS_DOMAINS = {"example.com", "scam.com"}
NOT_SAFE_DOMAINS = {"httpforever.com", "insecure-site.net", "badhttp.example"}
LIKELY_SAFE_DOMAINS = {"bankofamerica.com", "github.com", "login.microsoftonline.com","chess.com"}

FEATURES = [
    "DNSRecordType", "MXDnsResponse", "TXTDnsResponse", "HasSPFInfo", "HasDkimInfo", "HasDmarcInfo",
    "SubdomainNumber", "Entropy", "EntropyOfSubDomains", "StrangeCharacters", "ConsoantRatio",
    "NumericRatio", "SpecialCharRatio", "VowelRatio", "ConsoantSequence", "VowelSequence",
    "NumericSequence", "SpecialCharSequence", "DomainLength"
]

# --- 2. HELPER & CLASSIFICATION FUNCTIONS ---

def encode_features(feat_dict):
    df = pd.DataFrame([feat_dict])
    for col in df.columns:
        if df[col].dtype == 'object' or isinstance(df[col].iloc[0], str):
            df[col] = pd.factorize(df[col])[0]
        if df[col].dtype == 'bool':
            df[col] = df[col].astype(int)
    df.fillna(0, inplace=True)
    return df[FEATURES]

def calc_entropy(s):
    if not s: return 0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * log2(p) for p in prob if p > 0)

def char_ratio(s, mode):
    s = s.lower()
    if len(s) == 0: return 0
    vowels = "aeiou"
    consonants = "bcdfghjklmnpqrstvwxyz"
    digits = "0123456789"
    specials = "!@#$%^&*()_-+=~`[]{}|:;<>,.?/\\\"'"
    if mode == 'vowel': return sum(c in vowels for c in s) / len(s)
    if mode == 'consonant': return sum(c in consonants for c in s) / len(s)
    if mode == 'digit': return sum(c in digits for c in s) / len(s)
    if mode == 'special': return sum(c in specials for c in s) / len(s)
    return 0

def max_sequence(s, mode):
    s = s.lower()
    if mode == 'vowel': return max([len(m) for m in re.findall(r'[aeiou]+', s)] + [0])
    if mode == 'consonant': return max([len(m) for m in re.findall(r'[bcdfghjklmnpqrstvwxyz]+', s)] + [0])
    if mode == 'digit': return max([len(m) for m in re.findall(r'\d+', s)] + [0])
    if mode == 'special': return max([len(m) for m in re.findall(r'[^a-zA-Z0-9]+', s)] + [0])
    return 0

def classify_domain(domain, protocol):
    domain = domain.lower()
    if domain in BENIGN_DOMAINS: return "BENIGN", 1.0
    if domain in MALICIOUS_DOMAINS: return "MALWARE", 1.0
    if domain in NOT_SAFE_DOMAINS: return "NOT SAFE", 0.95
    if domain in LIKELY_SAFE_DOMAINS: return "LIKELY SAFE", 0.95

    tld = domain.split('.')[-1] if '.' in domain else domain
    subdomain = domain.replace(f".{tld}", "")
    sub_count = subdomain.count('.') + 1
    features = {
        "DNSRecordType": 1, "MXDnsResponse": False, "TXTDnsResponse": False, "HasSPFInfo": False,
        "HasDkimInfo": False, "HasDmarcInfo": False, "SubdomainNumber": sub_count,
        "Entropy": calc_entropy(domain), "EntropyOfSubDomains": calc_entropy(subdomain),
        "StrangeCharacters": sum(not c.isalnum() and c != '.' for c in domain),
        "ConsoantRatio": char_ratio(domain, 'consonant'), "NumericRatio": char_ratio(domain, 'digit'),
        "SpecialCharRatio": char_ratio(domain, 'special'), "VowelRatio": char_ratio(domain, 'vowel'),
        "ConsoantSequence": max_sequence(domain, 'consonant'), "VowelSequence": max_sequence(domain, 'vowel'),
        "NumericSequence": max_sequence(domain, 'digit'), "SpecialCharSequence": max_sequence(domain, 'special'),
        "DomainLength": len(domain)
    }
    try:
        encoded = encode_features(features)
        proba = model.predict_proba(encoded)[0]
        benign_conf = proba[model.classes_.tolist().index("benign")]
        malware_conf = proba[model.classes_.tolist().index("malware")]
        if malware_conf > 0.6: return "MALWARE", malware_conf
        elif benign_conf > 0.6: return "BENIGN", benign_conf
        else:
            if protocol == "HTTPS": return "LIKELY SAFE", 0.8
            elif protocol == "HTTP": return "NOT SAFE", 0.8
            else: return "BENIGN", 0.5
    except Exception as e:
        print(f"[!] Listener ML Error: {e}")
        return "UNKNOWN", 0.0

# --- 3. PACKET HANDLING & SNIFFING ---

def handle_packet(pkt):
    domain = None
    protocol = "Unknown"
    # Logic to extract domain and protocol from packet
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        try: domain, protocol = pkt[DNSQR].qname.decode().rstrip('.'), "DNS"
        except: return
    elif pkt.haslayer(HTTPRequest):
        try: domain, protocol = pkt[HTTPRequest].Host.decode(errors='ignore'), "HTTP"
        except: return
    elif pkt.haslayer(TCP) and pkt[TCP].dport == 443 and pkt.haslayer(Raw):
        if b"server_name" in (raw_load := pkt[Raw].load):
            try: domain, protocol = raw_load.split(b"server_name")[1][5:].split(b"\x00")[0].decode(), "HTTPS"
            except: return
    
    if domain:
        label, conf = classify_domain(domain, protocol)
        now = datetime.now().strftime('%H:%M:%S')
        print(f"[{now}] DETECTION: {domain:<30} | {protocol:<7} → {label} ({conf:.2f})")
        
        # --- Send detection to the server.py ---
        try:
            requests.post('http://127.0.0.1:5000/log', json={
                'time': now, 'domain': domain, 'protocol': protocol,
                'label': label, 'confidence': f"{conf:.2f}"
            }, timeout=1)
        except requests.exceptions.RequestException:
            # This will fail silently if the server.py is not running
            pass

if __name__ == '__main__':
    print("🚀 Starting packet sniffer... Will send logs to http://127.0.0.1:5000/log")
    sniff(filter="port 53 or port 80 or port 443", prn=handle_packet, store=False)
