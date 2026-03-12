from django.db import models


class Asset(models.Model):

    # ---------------------------
    # Asset Identification
    # ---------------------------
    domain = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    protocol = models.CharField(max_length=50, default="TLS")

    # ---------------------------
    # TLS / Crypto Details
    # ---------------------------
    tls_version = models.CharField(max_length=50, blank=True)
    cipher_suite = models.CharField(max_length=255, blank=True)

    issuer = models.TextField(blank=True)
    subject = models.TextField(blank=True)

    signature_algorithm = models.CharField(max_length=255, blank=True)

    key_type = models.CharField(max_length=50, blank=True)  # RSA / ECC
    key_size = models.CharField(max_length=50, blank=True)

    valid_from = models.DateTimeField(null=True, blank=True)
    valid_to = models.DateTimeField(null=True, blank=True)

    days_to_expiry = models.IntegerField(null=True, blank=True)

    # ---------------------------
    # PQC Security Posture
    # ---------------------------
    pqc_status = models.CharField(max_length=50)
    risk_score = models.IntegerField(default=0)

    # ---------------------------
    # Monitoring / Alerts
    # ---------------------------
    alert_flag = models.BooleanField(default=False)
    alert_message = models.TextField(blank=True)

    # ---------------------------
    # Scan Metadata
    # ---------------------------
    scan_status = models.CharField(max_length=50, default="Success")

    scan_type = models.CharField(
        max_length=50,
        default="single"
    )  # single / batch / discovery

    created_at = models.DateTimeField(auto_now_add=True)

    # ---------------------------
    # Display
    # ---------------------------
    def __str__(self):
        return f"{self.domain} ({self.tls_version})"
