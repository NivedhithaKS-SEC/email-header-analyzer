# ============================================================
# Email Header Analyzer — Backend
# Nivedhitha KS | Cybersecurity Portfolio
# Detects spoofing, phishing, and email authentication failures
# ============================================================

from flask import Flask, request, jsonify, render_template_string
import re
import socket
from datetime import datetime

app = Flask(__name__)

# ── ANALYSIS FUNCTIONS ──────────────────────────────────────

def parse_received_headers(raw):
    """Extract all Received: hops from headers."""
    hops = re.findall(r'Received:\s*(.*?)(?=\nReceived:|\nFrom:|\nTo:|\Z)', raw, re.DOTALL | re.IGNORECASE)
    result = []
    for h in hops[:6]:
        clean = ' '.join(h.split())
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', clean)
        by_match = re.search(r'by\s+([\w\.\-]+)', clean, re.IGNORECASE)
        result.append({
            "raw": clean[:200],
            "ip": ip_match.group(1) if ip_match else None,
            "by": by_match.group(1) if by_match else None
        })
    return result

def check_spf(raw):
    spf = re.search(r'Received-SPF:\s*(\w+)', raw, re.IGNORECASE)
    auth_results = re.search(r'spf=(\w+)', raw, re.IGNORECASE)
    val = None
    if spf:
        val = spf.group(1).lower()
    elif auth_results:
        val = auth_results.group(1).lower()
    if val == "pass":
        return {"status": "pass", "color": "green", "detail": "SPF check passed — sender IP is authorised"}
    elif val == "fail":
        return {"status": "fail", "color": "red", "detail": "SPF FAILED — sender IP not authorised to send for this domain"}
    elif val in ["softfail", "neutral"]:
        return {"status": "softfail", "color": "yellow", "detail": f"SPF {val} — weak authorisation, treat with caution"}
    return {"status": "none", "color": "gray", "detail": "SPF record not found or not checked"}

def check_dkim(raw):
    dkim = re.search(r'dkim=(\w+)', raw, re.IGNORECASE)
    if dkim:
        val = dkim.group(1).lower()
        if val == "pass":
            return {"status": "pass", "color": "green", "detail": "DKIM signature verified — email not tampered in transit"}
        elif val == "fail":
            return {"status": "fail", "color": "red", "detail": "DKIM FAILED — email may have been tampered or forged"}
        return {"status": val, "color": "yellow", "detail": f"DKIM result: {val}"}
    return {"status": "none", "color": "gray", "detail": "No DKIM signature found"}

def check_dmarc(raw):
    dmarc = re.search(r'dmarc=(\w+)', raw, re.IGNORECASE)
    if dmarc:
        val = dmarc.group(1).lower()
        if val == "pass":
            return {"status": "pass", "color": "green", "detail": "DMARC passed — domain alignment verified"}
        elif val in ["fail", "reject", "quarantine"]:
            return {"status": "fail", "color": "red", "detail": f"DMARC {val.upper()} — email fails domain policy"}
        return {"status": val, "color": "yellow", "detail": f"DMARC result: {val}"}
    return {"status": "none", "color": "gray", "detail": "No DMARC result found in headers"}

def extract_field(raw, field):
    m = re.search(rf'^{field}:\s*(.+)', raw, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else None

def check_reply_to_mismatch(raw):
    from_field = extract_field(raw, "From")
    reply_to   = extract_field(raw, "Reply-To")
    if from_field and reply_to:
        from_domain  = re.search(r'@([\w\.\-]+)', from_field)
        reply_domain = re.search(r'@([\w\.\-]+)', reply_to)
        if from_domain and reply_domain:
            if from_domain.group(1).lower() != reply_domain.group(1).lower():
                return True, f"From domain ({from_domain.group(1)}) ≠ Reply-To domain ({reply_domain.group(1)})"
    return False, None

def check_display_name_spoof(raw):
    from_field = extract_field(raw, "From")
    if not from_field:
        return False, None
    display = re.search(r'"?([^"<]+)"?\s*<', from_field)
    email_part = re.search(r'<([^>]+)>', from_field)
    if display and email_part:
        name = display.group(1).strip().lower()
        addr = email_part.group(1).lower()
        domain = re.search(r'@([\w\.\-]+)', addr)
        if domain:
            d = domain.group(1)
            trusted = ["google", "microsoft", "apple", "amazon", "paypal", "facebook", "linkedin", "netflix"]
            for t in trusted:
                if t in name and t not in d:
                    return True, f"Display name claims '{t}' but email is from '{d}'"
    return False, None

def detect_urgency_words(raw):
    subject = extract_field(raw, "Subject") or ""
    body_preview = raw[:2000]
    urgency = ["urgent", "immediately", "account suspended", "verify now",
               "act now", "limited time", "click here", "confirm your",
               "unusual activity", "unauthorized", "suspended", "expires"]
    found = [w for w in urgency if w.lower() in (subject + body_preview).lower()]
    return found

def calculate_risk_score(spf, dkim, dmarc, reply_mismatch, display_spoof, urgency_words, hops):
    score = 0
    flags = []

    if spf["status"] == "fail":
        score += 30; flags.append("SPF failed (+30)")
    elif spf["status"] == "none":
        score += 10; flags.append("No SPF record (+10)")
    elif spf["status"] == "softfail":
        score += 15; flags.append("SPF softfail (+15)")

    if dkim["status"] == "fail":
        score += 25; flags.append("DKIM failed (+25)")
    elif dkim["status"] == "none":
        score += 10; flags.append("No DKIM signature (+10)")

    if dmarc["status"] == "fail":
        score += 20; flags.append("DMARC failed (+20)")
    elif dmarc["status"] == "none":
        score += 5;  flags.append("No DMARC result (+5)")

    if reply_mismatch:
        score += 20; flags.append("Reply-To mismatch (+20)")

    if display_spoof:
        score += 25; flags.append("Display name spoofing (+25)")

    if len(urgency_words) >= 3:
        score += 15; flags.append(f"Urgency language: {urgency_words[:3]} (+15)")
    elif urgency_words:
        score += 5;  flags.append(f"Some urgency words (+5)")

    if len(hops) > 5:
        score += 5;  flags.append("Unusual hop count (+5)")

    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK — Likely phishing or spoofed"
        verdict_color = "red"
    elif score >= 40:
        verdict = "MEDIUM RISK — Suspicious, verify manually"
        verdict_color = "yellow"
    else:
        verdict = "LOW RISK — Appears legitimate"
        verdict_color = "green"

    return score, verdict, verdict_color, flags

def analyze_headers(raw_headers):
    spf     = check_spf(raw_headers)
    dkim    = check_dkim(raw_headers)
    dmarc   = check_dmarc(raw_headers)
    hops    = parse_received_headers(raw_headers)
    reply_mismatch, reply_detail = check_reply_to_mismatch(raw_headers)
    display_spoof, spoof_detail  = check_display_name_spoof(raw_headers)
    urgency = detect_urgency_words(raw_headers)
    score, verdict, verdict_color, flags = calculate_risk_score(
        spf, dkim, dmarc, reply_mismatch, display_spoof, urgency, hops)

    return {
        "fields": {
            "from":       extract_field(raw_headers, "From"),
            "to":         extract_field(raw_headers, "To"),
            "subject":    extract_field(raw_headers, "Subject"),
            "date":       extract_field(raw_headers, "Date"),
            "message_id": extract_field(raw_headers, "Message-ID"),
            "reply_to":   extract_field(raw_headers, "Reply-To"),
            "x_mailer":   extract_field(raw_headers, "X-Mailer"),
        },
        "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "hops": hops,
        "threat_indicators": {
            "reply_to_mismatch": {"detected": reply_mismatch, "detail": reply_detail},
            "display_name_spoof": {"detected": display_spoof, "detail": spoof_detail},
            "urgency_words": urgency,
        },
        "risk": {
            "score": score,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "flags": flags
        }
    }

# ── SAMPLE HEADERS FOR DEMO ─────────────────────────────────
SAMPLE_PHISHING = """From: "PayPal Security" <security-alert@paypa1-verify.com>
To: victim@gmail.com
Subject: URGENT: Your account has been suspended - Act immediately
Date: Mon, 20 Jan 2025 14:32:11 +0000
Message-ID: <abc123@paypa1-verify.com>
Reply-To: collect@suspicious-domain.ru
Received: from mail.suspicious-domain.ru ([198.51.100.42])
        by mx.gmail.com with SMTP id abc123
        for <victim@gmail.com>; Mon, 20 Jan 2025 14:32:11 +0000
Received: from unknown ([10.0.0.1]) by mail.suspicious-domain.ru
Received-SPF: fail (domain of paypa1-verify.com does not designate 198.51.100.42)
Authentication-Results: mx.gmail.com;
       dkim=fail header.i=@paypa1-verify.com;
       spf=fail smtp.mailfrom=paypa1-verify.com;
       dmarc=fail (p=REJECT) header.from=paypa1-verify.com
X-Mailer: PhishKit v2.3"""

SAMPLE_LEGIT = """From: "Google" <no-reply@accounts.google.com>
To: user@example.com
Subject: Security alert for your Google Account
Date: Tue, 21 Jan 2025 09:15:00 +0000
Message-ID: <xyz789@accounts.google.com>
Received: from mail-sor-f41.google.com ([209.85.220.41])
        by mx.example.com with SMTPS id abc
        for <user@example.com>; Tue, 21 Jan 2025 09:15:00 +0000
Received-SPF: pass (google.com: designates 209.85.220.41 as permitted sender)
Authentication-Results: mx.example.com;
       dkim=pass header.i=@accounts.google.com;
       spf=pass smtp.mailfrom=accounts.google.com;
       dmarc=pass (p=REJECT) header.from=google.com"""

@app.route('/')
def index():
    return render_template_string(open('templates/index.html', encoding='utf-8').read())

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    raw = data.get('headers', '').strip()
    if not raw:
        return jsonify({"error": "No headers provided"}), 400
    try:
        result = analyze_headers(raw)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/sample/<kind>')
def sample(kind):
    if kind == 'phishing':
        return jsonify({"headers": SAMPLE_PHISHING})
    return jsonify({"headers": SAMPLE_LEGIT})

if __name__ == '__main__':
    print("=" * 55)
    print("  EMAIL HEADER ANALYZER")
    print("  Nivedhitha KS | Cybersecurity Portfolio")
    print("  Open: http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=False, host='0.0.0.0', port=5000)
