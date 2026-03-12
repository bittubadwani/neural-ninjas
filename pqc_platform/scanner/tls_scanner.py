import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime


def scan_tls(domain):

    try:
        # Resolve IP
        ip_address = socket.gethostbyname(domain)

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                tls_version = ssock.version()
                cipher_suite = ssock.cipher()[0]

                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()

                signature_algorithm = cert.signature_hash_algorithm.name

                public_key = cert.public_key()

                key_size = getattr(public_key, "key_size", "Unknown")
                key_type = public_key.__class__.__name__

                valid_from = cert.not_valid_before
                valid_to = cert.not_valid_after

                # Days until expiry
                try:
                    days_to_expiry = (valid_to - datetime.utcnow()).days
                except:
                    days_to_expiry = None

                return {
                    "ip_address": ip_address,
                    "tls_version": tls_version,
                    "cipher_suite": cipher_suite,
                    "issuer": issuer,
                    "subject": subject,
                    "signature_algorithm": signature_algorithm,
                    "key_type": key_type,
                    "key_size": key_size,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "days_to_expiry": days_to_expiry,
                    "scan_status": "Success"
                }

    except Exception as e:

        return {
            "ip_address": None,
            "tls_version": "Unknown",
            "cipher_suite": "Unknown",
            "issuer": "Unknown",
            "subject": "Unknown",
            "signature_algorithm": "Unknown",
            "key_type": "Unknown",
            "key_size": "Unknown",
            "valid_from": None,
            "valid_to": None,
            "days_to_expiry": None,
            "scan_status": "Failed"
        }
