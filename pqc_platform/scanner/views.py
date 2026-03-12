from django.shortcuts import render
from .models import Asset
from .tls_scanner import scan_tls
from .pqc_validator import evaluate_pqc
from datetime import datetime
from django.contrib.auth.decorators import login_required

from django.http import JsonResponse, HttpResponse
import csv
import json
import pandas as pd
from io import BytesIO
from reportlab.pdfgen import canvas

# --------------------------------
# SECURITY CHANGE DETECTION
# --------------------------------
def detect_security_change(previous, new):

    alerts = []

    if previous.tls_version != new["tls_version"]:
        alerts.append("TLS version changed")

    if previous.cipher_suite != new["cipher_suite"]:
        alerts.append("Cipher suite changed")

    if previous.risk_score < new["risk_score"]:
        alerts.append("Risk score increased")

    if new["days_to_expiry"] and new["days_to_expiry"] < 30:
        alerts.append("Certificate expiring soon")

    return alerts


# --------------------------------
# SINGLE DOMAIN SCAN
# --------------------------------
@login_required
def scan_asset(request):

    if request.method == "POST":

        domain = request.POST.get("domain")

        scan_result = scan_tls(domain)

        pqc_status, risk = evaluate_pqc(
            scan_result["cipher_suite"],
            scan_result["tls_version"]
        )

        previous_asset = Asset.objects.filter(domain=domain).order_by('-created_at').first()

        alerts = []
        if previous_asset:
            alerts = detect_security_change(previous_asset, {
                "tls_version": scan_result["tls_version"],
                "cipher_suite": scan_result["cipher_suite"],
                "risk_score": risk,
                "days_to_expiry": scan_result["days_to_expiry"]
            })

        asset = Asset.objects.create(

            domain=domain,
            ip_address=scan_result["ip_address"],

            protocol="TLS",

            tls_version=scan_result["tls_version"],
            cipher_suite=scan_result["cipher_suite"],

            issuer=scan_result["issuer"],
            subject=scan_result["subject"],

            signature_algorithm=scan_result["signature_algorithm"],

            key_type=scan_result["key_type"],
            key_size=scan_result["key_size"],

            valid_from=scan_result["valid_from"],
            valid_to=scan_result["valid_to"],
            days_to_expiry=scan_result["days_to_expiry"],

            pqc_status=pqc_status,
            risk_score=risk,

            scan_status=scan_result["scan_status"],
            scan_type="single",

            alert_flag=len(alerts) > 0,
            alert_message=", ".join(alerts)
        )

        return render(request, "result.html", {"asset": asset})

    return render(request, "scan.html")


# --------------------------------
# BATCH DOMAIN SCAN
# --------------------------------
@login_required
def batch_scan(request):

    if request.method == "POST":

        domains_text = request.POST.get("domains")

        domains = domains_text.splitlines()

        results = []

        for domain in domains:

            domain = domain.strip()

            if not domain:
                continue

            scan_result = scan_tls(domain)

            pqc_status, risk = evaluate_pqc(
                scan_result["cipher_suite"],
                scan_result["tls_version"]
            )

            asset = Asset.objects.create(

                domain=domain,
                ip_address=scan_result["ip_address"],

                protocol="TLS",

                tls_version=scan_result["tls_version"],
                cipher_suite=scan_result["cipher_suite"],

                issuer=scan_result["issuer"],
                subject=scan_result["subject"],

                signature_algorithm=scan_result["signature_algorithm"],

                key_type=scan_result["key_type"],
                key_size=scan_result["key_size"],

                valid_from=scan_result["valid_from"],
                valid_to=scan_result["valid_to"],
                days_to_expiry=scan_result["days_to_expiry"],

                pqc_status=pqc_status,
                risk_score=risk,

                scan_status=scan_result["scan_status"],
                scan_type="batch"
            )

            results.append(asset)

        return render(request, "batch_result.html", {"assets": results})

    return render(request, "scan.html")


# --------------------------------
# ASSET INVENTORY
# --------------------------------
@login_required
def asset_inventory(request):

    assets = Asset.objects.all().order_by('-created_at')

    return render(request, "assets.html", {"assets": assets})


# --------------------------------
# CBOM VIEW
# --------------------------------
@login_required
def cbom_view(request):

    assets = Asset.objects.all().order_by('-created_at')

    return render(request, "cbom.html", {"assets": assets})


# --------------------------------
# CYBER RATING
# --------------------------------
def calculate_cyber_rating(assets):

    if not assets.exists():
        return "N/A"

    avg_risk = sum(a.risk_score for a in assets) / assets.count()

    if avg_risk <= 20:
        return "A+"
    elif avg_risk <= 30:
        return "A"
    elif avg_risk <= 40:
        return "A-"
    elif avg_risk <= 60:
        return "B"
    else:
        return "C"


# --------------------------------
# RECOMMENDATION ENGINE
# --------------------------------
def generate_recommendations(assets):

    recommendations = set()

    for asset in assets:

        if asset.tls_version in ["TLSv1", "TLSv1.1", "TLSv1.2"]:
            recommendations.add("Upgrade servers to TLS 1.3.")

        if "RSA" in asset.cipher_suite:
            recommendations.add("Plan migration from RSA to PQC-ready algorithms.")

        try:
            if int(asset.key_size) < 2048:
                recommendations.add("Increase cryptographic key size to at least 2048 bits.")
        except:
            pass

        if asset.days_to_expiry and asset.days_to_expiry < 30:
            recommendations.add("Renew certificates expiring within 30 days.")

        if asset.pqc_status == "Critical":
            recommendations.add("Critical assets should be prioritized for PQC migration.")

    return list(recommendations)


# --------------------------------
# PQC POSTURE ANALYTICS
# --------------------------------
@login_required
def pqc_posture(request):

    assets = Asset.objects.all()

    total_assets = assets.count()

    pqc_ready = assets.filter(pqc_status="PQC Ready").count()
    standard = assets.filter(pqc_status="Standard").count()
    legacy = assets.filter(pqc_status="Legacy").count()
    critical = assets.filter(pqc_status="Critical").count()

    low_risk = assets.filter(risk_score__lt=30).count()
    medium_risk = assets.filter(risk_score__gte=30, risk_score__lt=60).count()
    high_risk = assets.filter(risk_score__gte=60).count()

    cyber_rating = calculate_cyber_rating(assets)

    recommendations = generate_recommendations(assets)

    context = {

        "total_assets": total_assets,

        "pqc_ready": pqc_ready,
        "standard": standard,
        "legacy": legacy,
        "critical": critical,

        "low_risk": low_risk,
        "medium_risk": medium_risk,
        "high_risk": high_risk,

        "cyber_rating": cyber_rating,
        "recommendations": recommendations,

        "assets": assets
    }

    return render(request, "pqc_posture.html", context)


@login_required
def dashboard(request):

    assets = Asset.objects.all()

    total_assets = assets.count()

    pqc_ready = assets.filter(pqc_status="PQC Ready").count()
    standard = assets.filter(pqc_status="Standard").count()
    legacy = assets.filter(pqc_status="Legacy").count()
    critical = assets.filter(pqc_status="Critical").count()

    low_risk = assets.filter(risk_score__lt=30).count()
    medium_risk = assets.filter(risk_score__gte=30, risk_score__lt=60).count()
    high_risk = assets.filter(risk_score__gte=60).count()

    cyber_rating = calculate_cyber_rating(assets)

    context = {
        "total_assets": total_assets,
        "pqc_ready": pqc_ready,
        "standard": standard,
        "legacy": legacy,
        "critical": critical,
        "low_risk": low_risk,
        "medium_risk": medium_risk,
        "high_risk": high_risk,
        "cyber_rating": cyber_rating,
        "assets": assets[:10]
    }

    return render(request, "dashboard.html", context)
    
    
    
def reporting_page(request):

    return render(request, "reporting.html")







def generate_report(request):

    assets = Asset.objects.all()

    format_type = request.POST.get("format")

    data = []

    for a in assets:

        data.append({
            "Domain": a.domain,
            "IP": a.ip_address,
            "TLS Version": a.tls_version,
            "Cipher": a.cipher_suite,
            "PQC Status": a.pqc_status,
            "Risk Score": a.risk_score
        })


    # ---------------- JSON EXPORT ----------------

    if format_type == "json":

        response = HttpResponse(
            json.dumps(data, indent=4),
            content_type="application/json"
        )

        response["Content-Disposition"] = "attachment; filename=report.json"

        return response


    # ---------------- CSV EXPORT ----------------

    if format_type == "csv":

        response = HttpResponse(content_type="text/csv")

        response["Content-Disposition"] = "attachment; filename=report.csv"

        writer = csv.writer(response)

        writer.writerow([
            "Domain",
            "IP",
            "TLS Version",
            "Cipher",
            "PQC Status",
            "Risk Score"
        ])

        for row in data:

            writer.writerow([
                row["Domain"],
                row["IP"],
                row["TLS Version"],
                row["Cipher"],
                row["PQC Status"],
                row["Risk Score"]
            ])

        return response


    # ---------------- EXCEL EXPORT ----------------

    if format_type == "excel":

        df = pd.DataFrame(data)

        buffer = BytesIO()

        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Report")

        buffer.seek(0)

        response = HttpResponse(
            buffer,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        response["Content-Disposition"] = "attachment; filename=report.xlsx"

        return response


    # ---------------- PDF EXPORT ----------------

    if format_type == "pdf":

        buffer = BytesIO()

        p = canvas.Canvas(buffer)

        p.setFont("Helvetica", 12)

        y = 800

        p.drawString(200, 820, "PQC Security Report")

        for d in data:

            line = f"{d['Domain']} | {d['TLS Version']} | {d['Cipher']} | {d['PQC Status']} | Risk {d['Risk Score']}"

            p.drawString(50, y, line)

            y -= 20

            if y < 50:
                p.showPage()
                p.setFont("Helvetica", 12)
                y = 800

        p.save()

        buffer.seek(0)

        response = HttpResponse(buffer, content_type="application/pdf")

        response["Content-Disposition"] = "attachment; filename=report.pdf"

        return response


    return HttpResponse("Invalid format")
