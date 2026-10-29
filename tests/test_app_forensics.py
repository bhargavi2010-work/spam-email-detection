"""
Integration test for the /analyze-email endpoint in app.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
import json

def test_endpoint():
    client = app.test_client()

    sample_email = """Received: from mail.attacker-server.ru (mail.attacker-server.ru [185.220.101.5])
        by mx.targetcorp.com with ESMTP id q41si8274981plb;
        Thu, 29 Oct 2026 02:20:00 -0700
Authentication-Results: mx.targetcorp.com;
       spf=fail;
       dkim=fail;
       dmarc=fail action=none header.from=paypal.com
From: "PayPal Security Alert" <phisher@rogue-host.xyz>
Reply-To: drop@rogue-collector.com
To: user@targetcorp.com
Subject: Urgent: Verify your credentials or account will be suspended!
Date: Thu, 29 Oct 2026 09:20:00 +0000

Dear customer,
Congratulations! You've won a $1000 gift card. Claim now!
"""

    response = client.post(
        '/analyze-email',
        data=json.dumps({'raw_email': sample_email}),
        content_type='application/json'
    )

    print("Response status code:", response.status_code)
    data = response.get_json()
    assert response.status_code == 200
    assert data["status"] == "success"
    
    forensics = data["data"]
    print("Origin IP:", forensics["traceability"]["origin_ip"])
    print("Risk Score:", forensics["forensic_assessment"]["risk_score"])
    print("Risk Level:", forensics["forensic_assessment"]["risk_level"])
    print("NLP Result:", forensics["nlp_analysis"])
    print("[PASS] Flask /analyze-email endpoint integration test passed!")

if __name__ == '__main__':
    test_endpoint()
