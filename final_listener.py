import joblib
import socket
import pandas as pd
from scapy.all import sniff, DNS, DNSQR, IP, TCP, Raw
from scapy.layers.http import HTTPRequest
from datetime import datetime
from math import log2
import re

# Load trained model
model = joblib.load("C:\\Users\\anees\\Downloads\\OBJECT DETECTION\\dns_spoof_detector\\data\\model\\final_model\\1dns_binary_rf_model_optimized.joblib")

# Local IP
CURRENT_IP = socket.gethostbyname(socket.gethostname())
print(f"🚨 Real-Time DNS+HTTP/HTTPS Threat Detector ({CURRENT_IP})")


# Features expected by model
FEATURES = [
    "DNSRecordType", "MXDnsResponse", "TXTDnsResponse", "HasSPFInfo", "HasDkimInfo", "HasDmarcInfo",
    "SubdomainNumber", "Entropy", "EntropyOfSubDomains", "StrangeCharacters", "ConsoantRatio",
    "NumericRatio", "SpecialCharRatio", "VowelRatio", "ConsoantSequence", "VowelSequence",
    "NumericSequence", "SpecialCharSequence", "DomainLength"
]

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
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * log2(p) for p in prob if p > 0)

def char_ratio(s, mode):
    s = s.lower()
    vowels = "aeiou"
    consonants = "bcdfghjklmnpqrstvwxyz"
    digits = "0123456789"
    specials = "!@#$%^&*()_-+=~`[]{}|:;<>,.?/\\\"'"
    if len(s) == 0: return 0
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
    tld = domain.split('.')[-1] if '.' in domain else domain
    subdomain = domain.replace(f".{tld}", "")
    sub_count = subdomain.count('.') + 1

    features = {
        "DNSRecordType": 1,
        "MXDnsResponse": False, "TXTDnsResponse": False, "HasSPFInfo": False,
        "HasDkimInfo": False, "HasDmarcInfo": False,
        "SubdomainNumber": sub_count,
        "Entropy": calc_entropy(domain),
        "EntropyOfSubDomains": calc_entropy(subdomain),
        "StrangeCharacters": sum(not c.isalnum() and c != '.' for c in domain),
        "ConsoantRatio": char_ratio(domain, 'consonant'),
        "NumericRatio": char_ratio(domain, 'digit'),
        "SpecialCharRatio": char_ratio(domain, 'special'),
        "VowelRatio": char_ratio(domain, 'vowel'),
        "ConsoantSequence": max_sequence(domain, 'consonant'),
        "VowelSequence": max_sequence(domain, 'vowel'),
        "NumericSequence": max_sequence(domain, 'digit'),
        "SpecialCharSequence": max_sequence(domain, 'special'),
        "DomainLength": len(domain)
    }

    if domain in BENIGN_DOMAINS:
        return "BENIGN", 1.0
    if domain in MALICIOUS_DOMAINS:
        return "MALWARE", 1.0

    try:
        encoded = encode_features(features)
        proba = model.predict_proba(encoded)[0]
        benign_conf = proba[model.classes_.tolist().index("benign")]
        malware_conf = proba[model.classes_.tolist().index("malware")]

        # Hard override: remove UNCERTAIN and force protocol fallback
        if malware_conf > 0.6:
            return "MALWARE", malware_conf
        elif benign_conf > 0.6:
            return "BENIGN", benign_conf
        else:
            # Protocol fallback
            if protocol == "HTTPS":
                return "LIKELY SAFE", 0.8
            elif protocol == "HTTP":
                return "NOT SAFE", 0.8
            else:
                return "BENIGN", 0.5  # fallback
    except Exception as e:
        print(f"[!] ML Error: {e}")
        return "UNKNOWN", 0.0

def handle_packet(pkt):
    domain = None
    protocol = "Unknown"

    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        try:
            domain = pkt[DNSQR].qname.decode().rstrip('.')
            protocol = "DNS"
        except:
            return

    elif pkt.haslayer(HTTPRequest):
        try:
            domain = pkt[HTTPRequest].Host.decode(errors='ignore')
            protocol = "HTTP"
        except:
            return

    elif pkt.haslayer(TCP) and pkt[TCP].dport == 443 and pkt.haslayer(Raw):
        raw_load = pkt[Raw].load
        if b"server_name" in raw_load:
            try:
                domain = raw_load.split(b"server_name")[1][5:].split(b"\x00")[0].decode(errors='ignore')
                protocol = "HTTPS"
            except:
                return

    if domain:
        label, conf = classify_domain(domain, protocol)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] DOMAIN: {domain:<30} | {protocol:<7} → {label} ({conf:.2f})")

# Start sniffing
sniff(filter="port 53 or port 80 or port 443", prn=handle_packet, store=False)
