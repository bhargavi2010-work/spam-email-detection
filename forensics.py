"""
Forensic Analysis & Protocol Inspection Engine
Analyzes raw email files (.eml) or headers to detect spoofing, protocol authentication failures,
relay anomalies, and origin IP traceability.
"""

import email
from email import policy
from email.parser import BytesParser, Parser
import re
import ipaddress
import hashlib
from typing import Dict, List, Any, Optional, Tuple


# Common trusted brands frequently targeted for display-name spoofing
TARGETED_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "netflix": ["netflix.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
    "bank": [], # Generic financial cue
    "security": [],
    "support": [],
    "admin": [],
    "it service": [],
}


class EmailForensicsEngine:
    """Performs deep header forensics, protocol inspection, and hop traceability."""

    def __init__(self):
        # Regex to extract IP addresses (IPv4)
        self.ipv4_regex = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        # Regex for email address extraction
        self.email_regex = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

    def parse_eml(self, raw_content: Any) -> Dict[str, Any]:
        """
        Ingests raw .eml file content (bytes or str) and returns comprehensive
        forensic analysis and metadata.
        """
        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode('utf-8', errors='replace')
            msg = Parser(policy=policy.default).parsestr(raw_content)
        else:
            raw_bytes = raw_content
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        # Cryptographic hash for chain of custody
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        md5_hash = hashlib.md5(raw_bytes).hexdigest()

        # Basic metadata
        subject = str(msg.get('Subject', '') or '')
        from_header = str(msg.get('From', '') or '')
        to_header = str(msg.get('To', '') or '')
        reply_to = str(msg.get('Reply-To', '') or '')
        return_path = str(msg.get('Return-Path', '') or '')
        message_id = str(msg.get('Message-ID', '') or '')
        date = str(msg.get('Date', '') or '')

        # Extract From details
        from_name, from_email, from_domain = self._parse_address_field(from_header)
        _, reply_to_email, reply_to_domain = self._parse_address_field(reply_to)
        _, return_path_email, return_path_domain = self._parse_address_field(return_path)

        # Extract message body
        body_plain, body_html = self._extract_body(msg)

        # Extract attachments
        attachments = self._extract_attachments(msg)

        # Protocol checks (SPF, DKIM, DMARC)
        auth_results = self._analyze_authentication(msg)

        # Relay hops & Origin IP
        relay_hops, origin_ip = self._analyze_received_headers(msg)

        # Spoofing & Mismatch Checks
        spoofing_checks = self._detect_spoofing(
            from_name=from_name,
            from_email=from_email,
            from_domain=from_domain,
            reply_to_domain=reply_to_domain,
            return_path_domain=return_path_domain,
            auth_results=auth_results
        )

        # Compute forensic threat score & findings
        risk_score, risk_level, findings = self._compute_risk_score(
            auth_results=auth_results,
            spoofing_checks=spoofing_checks,
            origin_ip=origin_ip,
            attachments=attachments
        )

        return {
            "forensic_evidence": {
                "sha256": sha256_hash,
                "md5": md5_hash,
                "timestamp": date,
                "message_id": message_id
            },
            "envelope": {
                "from_header": from_header,
                "from_name": from_name,
                "from_email": from_email,
                "from_domain": from_domain,
                "to": to_header,
                "subject": subject,
                "reply_to": reply_to_email,
                "return_path": return_path_email
            },
            "body": {
                "plain": body_plain,
                "html_length": len(body_html) if body_html else 0,
                "has_html": bool(body_html)
            },
            "attachments": attachments,
            "authentication": auth_results,
            "traceability": {
                "origin_ip": origin_ip,
                "total_hops": len(relay_hops),
                "relay_hops": relay_hops
            },
            "spoofing_checks": spoofing_checks,
            "forensic_assessment": {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "findings": findings
            }
        }

    def _parse_address_field(self, field_value: str) -> Tuple[str, str, str]:
        """Extracts display name, email, and domain from address headers."""
        if not field_value:
            return "", "", ""

        # Extract email address
        emails = self.email_regex.findall(field_value)
        email_addr = emails[0].lower() if emails else ""
        domain = email_addr.split('@')[-1] if '@' in email_addr else ""

        # Extract display name (text outside angle brackets or quotes)
        name = field_value
        if '<' in name:
            name = name.split('<')[0].strip(' "\'')
        elif email_addr:
            name = name.replace(email_addr, '').strip(' "\'')

        return name, email_addr, domain

    def _extract_body(self, msg) -> Tuple[str, str]:
        """Recursively extracts plain text and HTML body parts."""
        body_plain = ""
        body_html = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition") or "")
                if "attachment" in content_disposition:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or 'utf-8'
                    text = payload.decode(charset, errors='replace')
                    if content_type == 'text/plain' and not body_plain:
                        body_plain = text
                    elif content_type == 'text/html' and not body_html:
                        body_html = text
                except Exception:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    text = payload.decode(charset, errors='replace')
                    if msg.get_content_type() == 'text/html':
                        body_html = text
                    else:
                        body_plain = text
            except Exception:
                pass

        return body_plain.strip(), body_html.strip()

    def _extract_attachments(self, msg) -> List[Dict[str, Any]]:
        """Extracts attachment metadata including filenames, types, and hashes."""
        attachments = []
        if not msg.is_multipart():
            return attachments

        for part in msg.walk():
            disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if "attachment" in disposition or filename:
                payload = part.get_payload(decode=True) or b""
                file_hash = hashlib.sha256(payload).hexdigest() if payload else ""
                content_type = part.get_content_type()
                size_bytes = len(payload)

                # Check for suspicious file extensions
                suspicious = bool(re.search(
                    r'\.(exe|vbs|bat|cmd|ps1|scr|js|jar|iso|hta|dll|pif)$',
                    filename or "",
                    re.IGNORECASE
                ))

                attachments.append({
                    "filename": filename or "unnamed_attachment",
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                    "sha256": file_hash,
                    "is_suspicious": suspicious
                })

        return attachments

    def _analyze_authentication(self, msg) -> Dict[str, Any]:
        """Parses SPF, DKIM, and DMARC status from security headers."""
        auth_results_header = str(msg.get('Authentication-Results', '') or '')
        received_spf = str(msg.get('Received-SPF', '') or '')
        dkim_signature = msg.get('DKIM-Signature', None)

        # Default statuses
        spf_status = "UNKNOWN"
        dkim_status = "NONE" if dkim_signature is None else "SIGNED"
        dmarc_status = "UNKNOWN"

        combined_headers = f"{auth_results_header} {received_spf}".lower()

        # SPF Parsing
        if "spf=pass" in combined_headers or "pass" in received_spf.lower():
            spf_status = "PASS"
        elif "spf=fail" in combined_headers or "fail" in received_spf.lower():
            spf_status = "FAIL"
        elif "spf=softfail" in combined_headers or "softfail" in received_spf.lower():
            spf_status = "SOFTFAIL"
        elif "spf=neutral" in combined_headers:
            spf_status = "NEUTRAL"
        elif "spf=none" in combined_headers:
            spf_status = "NONE"

        # DKIM Parsing
        if "dkim=pass" in combined_headers:
            dkim_status = "PASS"
        elif "dkim=fail" in combined_headers:
            dkim_status = "FAIL"
        elif dkim_signature is not None and dkim_status == "SIGNED":
            dkim_status = "PRESENT (Not Verified by MTA)"

        # DMARC Parsing
        if "dmarc=pass" in combined_headers:
            dmarc_status = "PASS"
        elif "dmarc=fail" in combined_headers:
            dmarc_status = "FAIL"
        elif "dmarc=none" in combined_headers:
            dmarc_status = "NONE"

        return {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "has_dkim_signature": dkim_signature is not None,
            "raw_auth_results": auth_results_header[:300] if auth_results_header else "None"
        }

    def _analyze_received_headers(self, msg) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Parses all 'Received:' headers in transmission order (earliest/oldest to latest)
        and extracts public IP hops to identify the true origin IP.
        """
        raw_received = msg.get_all('Received', [])
        if not raw_received:
            return [], None

        # Received headers are stored top-to-bottom (latest to earliest).
        # We reverse them to get the actual transmission sequence: Client -> Hop 1 -> Hop 2 -> Destination
        chronological_hops = list(reversed(raw_received))
        parsed_hops = []
        origin_ip = None

        for idx, hop_str in enumerate(chronological_hops, start=1):
            hop_clean = " ".join(hop_str.split())

            # Find all IPv4 addresses in this hop
            ips = self.ipv4_regex.findall(hop_clean)
            public_ips = []
            private_ips = []

            for ip_addr in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_addr)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                        private_ips.append(ip_addr)
                    else:
                        public_ips.append(ip_addr)
                except ValueError:
                    continue

            # Extract server names (from ... by ...)
            from_server = ""
            by_server = ""
            from_match = re.search(r'from\s+([^\s\(\)]+)', hop_clean, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s\(\)]+)', hop_clean, re.IGNORECASE)
            if from_match:
                from_server = from_match.group(1)
            if by_match:
                by_server = by_match.group(1)

            # Earliest public IP found across hops is our candidate origin IP
            if not origin_ip and public_ips:
                origin_ip = public_ips[0]

            parsed_hops.append({
                "hop_number": idx,
                "from_server": from_server,
                "by_server": by_server,
                "public_ips": public_ips,
                "private_ips": private_ips,
                "raw_hop": hop_clean[:200]
            })

        return parsed_hops, origin_ip

    def _detect_spoofing(
        self,
        from_name: str,
        from_email: str,
        from_domain: str,
        reply_to_domain: str,
        return_path_domain: str,
        auth_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detects display-name spoofing, lookalike patterns, and envelope mismatches."""
        indicators = []
        is_display_name_spoofed = False
        is_reply_to_mismatch = False
        is_return_path_mismatch = False

        # 1. Check Display Name Spoofing with embedded emails (e.g. From: "security@paypal.com" <evil@attacker.xyz>)
        if from_name:
            embedded_emails = self.email_regex.findall(from_name)
            if embedded_emails:
                embedded_domain = embedded_emails[0].split('@')[-1].lower()
                if embedded_domain != from_domain:
                    is_display_name_spoofed = True
                    indicators.append(
                        f"Display name impersonation: Name contains '{embedded_emails[0]}' but actual sender is '{from_email}'"
                    )

            # 2. Check Display Name impersonating major brands
            name_lower = from_name.lower()
            for brand, legitimate_domains in TARGETED_BRANDS.items():
                if brand in name_lower and legitimate_domains:
                    if from_domain and not any(from_domain.endswith(legit) for legit in legitimate_domains):
                        is_display_name_spoofed = True
                        indicators.append(
                            f"Brand Impersonation: Display name mentions '{brand.capitalize()}', but email domain is '{from_domain}'"
                        )

        # 3. Check Reply-To Mismatch (often used to redirect responses to attacker)
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            is_reply_to_mismatch = True
            indicators.append(
                f"Reply-To Mismatch: Responses will be routed to '@{reply_to_domain}' instead of sender '@{from_domain}'"
            )

        # 4. Check Return-Path Mismatch
        if return_path_domain and from_domain and return_path_domain != from_domain:
            is_return_path_mismatch = True
            indicators.append(
                f"Return-Path Mismatch: Bounces sent to '@{return_path_domain}', differing from sender domain '@{from_domain}'"
            )

        return {
            "is_display_name_spoofed": is_display_name_spoofed,
            "is_reply_to_mismatch": is_reply_to_mismatch,
            "is_return_path_mismatch": is_return_path_mismatch,
            "spoofing_indicators": indicators
        }

    def _compute_risk_score(
        self,
        auth_results: Dict[str, Any],
        spoofing_checks: Dict[str, Any],
        origin_ip: Optional[str],
        attachments: List[Dict[str, Any]]
    ) -> Tuple[int, str, List[str]]:
        """Calculates a baseline forensic risk score (0-100) based on header/protocol findings."""
        score = 0
        findings = []

        # SPF Check
        if auth_results["spf"] == "FAIL":
            score += 30
            findings.append("CRITICAL: SPF Authentication Failed (Sender IP is not authorized for this domain)")
        elif auth_results["spf"] == "SOFTFAIL":
            score += 15
            findings.append("WARNING: SPF Softfail (Mail likely unauthorized)")
        elif auth_results["spf"] == "NONE":
            score += 10
            findings.append("NOTICE: Sender domain does not publish an SPF record")

        # DKIM Check
        if auth_results["dkim"] == "FAIL":
            score += 25
            findings.append("CRITICAL: DKIM Cryptographic Signature verification Failed (Email altered in transit)")
        elif auth_results["dkim"] == "NONE":
            score += 10
            findings.append("NOTICE: No DKIM digital signature found")

        # DMARC Check
        if auth_results["dmarc"] == "FAIL":
            score += 35
            findings.append("CRITICAL: DMARC Policy Failed (Domain alignment rejected)")

        # Spoofing Checks
        if spoofing_checks["is_display_name_spoofed"]:
            score += 35
            findings.extend(spoofing_checks["spoofing_indicators"])

        if spoofing_checks["is_reply_to_mismatch"]:
            score += 20
            findings.append("WARNING: Reply-To domain does not match From domain")

        # Origin IP
        if not origin_ip:
            score += 10
            findings.append("NOTICE: Unable to determine public originating IP from Received headers")

        # Suspicious Attachments
        suspicious_attachments = [a["filename"] for a in attachments if a.get("is_suspicious")]
        if suspicious_attachments:
            score += 40
            findings.append(f"CRITICAL: Highly dangerous executable/script attachments detected: {', '.join(suspicious_attachments)}")

        # Clamp score between 0 and 100
        score = min(max(score, 0), 100)

        # Risk Level
        if score >= 70:
            level = "MALICIOUS / HIGH RISK"
        elif score >= 40:
            level = "SUSPICIOUS"
        elif score >= 20:
            level = "LOW RISK"
        else:
            level = "CLEAN / LEGITIMATE"

        return score, level, findings
