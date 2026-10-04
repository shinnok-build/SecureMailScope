# -*- coding: utf-8 -*-
"""Remediation guidance, one line per policy rule.

Kept in its own module so the report layer, the console and the analysis CLI all quote the
same wording: a finding and its fix can never drift apart.
"""

REMEDIATION = {
 "A1": "Enforce MTA-STS (RFC 8461) + TLS-RPT (RFC 8460) on every outbound MTA; alert on any stream that advertises STARTTLS and never upgrades.",
 "W1": "Disable TLS 1.0 on all mail listeners (RFC 8996 historic). Minimum TLS 1.2 per NIST SP 800-52r2.",
 "W2": "Disable TLS 1.1 on all mail listeners (RFC 8996 historic). Minimum TLS 1.2 per NIST SP 800-52r2.",
 "W3": "Restrict cipher suites to the AEAD set (TLS_ECDHE_*_GCM / TLS 1.3 suites). Remove RC4, 3DES and CBC-SHA1.",
 "W4": "Disable static-RSA key exchange; require (EC)DHE so captured mail stays safe after key compromise.",
 "W5": "Automate certificate renewal; alert at 30 days to expiry (RFC 5280 validity).",
 "W6": "Reissue certificates with RSA >= 2048 bits or ECDSA P-256 (NIST SP 800-57).",
 "W7": "Reissue certificates signed with SHA-256 or better (RFC 9155 deprecates SHA-1 signatures).",
 "W8": "Reissue certificate with the mail host in subjectAltName; clients must match per RFC 6125.",
 "A2": "Anchor mail certificates in the enterprise/CA-Browser-Forum-trusted PKI; reject self-signed leaves (RFC 5280 path validation).",
 "A3": "Investigate the endpoint: a minimal hand-rolled TLS stack on mail traffic is an implant/evasion indicator.",
 "W9": "Pin every listener to IANA-assigned AEAD suites; treat an unassigned suite id as a red flag, never a silent pass.",
 "W10": "Reissue the leaf with extendedKeyUsage = serverAuth (RFC 5280 s4.2.1.12).",
 "W11": "Reissue with a validity of 398 days or less (CA/B Forum BR s4.2.1); automate renewal.",
 "A4": "Treat aborted post-STARTTLS handshakes as hostile: run MTA-STS (RFC 8461) in enforce mode and alert on any handshake that starts and never completes.",
}

