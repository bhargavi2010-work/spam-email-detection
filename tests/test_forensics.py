"""
Unit tests to verify EmailForensicsEngine against legitimate, spoofed, and phishing emails.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from forensics import EmailForensicsEngine

def test_legitimate_email():
    raw_email = """Delivered-To: recipient@example.com
Received: by 2002:a05:6808:1493:b0:3c9:4b10:8e92 with SMTP id e18csp3780332oiw;
        Thu, 29 Oct 2026 01:15:00 -0700 (PDT)
Received: from mail-ed1-f52.google.com (mail-ed1-f52.google.com. [209.85.208.52])
        by mx.google.com with ESMTPS id o12si2341235edp.439.2026.10.29.01.14.59
        for <recipient@example.com>;
        Thu, 29 Oct 2026 01:14:59 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601;
       spf=pass (google.com: domain of support@google.com designates 209.85.208.52 as permitted sender) smtp.mailfrom=support@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=20230601;
From: "Google Security" <support@google.com>
To: recipient@example.com
Subject: Security Alert: New sign-in detected
Date: Thu, 29 Oct 2026 08:14:59 +0000
Message-ID: <CABk9=j1234567@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"

Hi User,
We detected a new sign-in to your Google Account on a Windows device.
If this was you, you don't need to do anything.
"""
    engine = EmailForensicsEngine()
    result = engine.parse_eml(raw_email)
    print("--- Legitimate Email Test ---")
    print("Origin IP:", result["traceability"]["origin_ip"])
    print("SPF:", result["authentication"]["spf"])
    print("DKIM:", result["authentication"]["dkim"])
    print("DMARC:", result["authentication"]["dmarc"])
    print("Risk Score:", result["forensic_assessment"]["risk_score"])
    print("Risk Level:", result["forensic_assessment"]["risk_level"])
    print("Findings:", result["forensic_assessment"]["findings"])
    assert result["authentication"]["spf"] == "PASS"
    assert result["authentication"]["dkim"] == "PASS"
    assert result["authentication"]["dmarc"] == "PASS"
    assert result["forensic_assessment"]["risk_level"] == "CLEAN / LEGITIMATE"
    print("[PASS] Legitimate Email Test Passed!\n")

def test_spoofed_phishing_email():
    raw_email = """Received: from mail.attacker-server.ru (mail.attacker-server.ru [185.220.101.5])
        by mx.targetcorp.com with ESMTP id q41si8274981plb;
        Thu, 29 Oct 2026 02:20:00 -0700
Authentication-Results: mx.targetcorp.com;
       spf=fail (targetcorp.com: domain of admin@paypal.com does not designate 185.220.101.5 as permitted sender);
       dkim=fail;
       dmarc=fail action=none header.from=paypal.com
From: "PayPal Account Security" <scammer@rogue-host.xyz>
Reply-To: harvest-creds@attacker-drop.com
Return-Path: <bounces@hacked-domain.net>
To: victim@targetcorp.com
Subject: URGENT: Your PayPal Account will be locked in 24 hours!
Date: Thu, 29 Oct 2026 09:20:00 +0000
Message-ID: <spoofed123@attacker.xyz>
Content-Type: text/plain; charset="UTF-8"

Dear Customer,
Your account has been suspended due to suspicious activity.
Please verify your credentials immediately.
"""
    engine = EmailForensicsEngine()
    result = engine.parse_eml(raw_email)
    print("--- Spoofed Phishing Email Test ---")
    print("Origin IP:", result["traceability"]["origin_ip"])
    print("Display Name Spoofed:", result["spoofing_checks"]["is_display_name_spoofed"])
    print("Reply-To Mismatch:", result["spoofing_checks"]["is_reply_to_mismatch"])
    print("SPF:", result["authentication"]["spf"])
    print("DKIM:", result["authentication"]["dkim"])
    print("DMARC:", result["authentication"]["dmarc"])
    print("Risk Score:", result["forensic_assessment"]["risk_score"])
    print("Risk Level:", result["forensic_assessment"]["risk_level"])
    print("Findings:", result["forensic_assessment"]["findings"])
    assert result["spoofing_checks"]["is_display_name_spoofed"] is True
    assert result["spoofing_checks"]["is_reply_to_mismatch"] is True
    assert result["authentication"]["spf"] == "FAIL"
    assert result["forensic_assessment"]["risk_score"] >= 70
    assert "MALICIOUS" in result["forensic_assessment"]["risk_level"]
    print("[PASS] Spoofed Phishing Email Test Passed!\n")

if __name__ == '__main__':
    test_legitimate_email()
    test_spoofed_phishing_email()
