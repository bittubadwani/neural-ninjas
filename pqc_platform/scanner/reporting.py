import pandas as pd
from io import BytesIO
from django.http import HttpResponse
from reportlab.pdfgen import canvas
from .models import Asset


def generate_dataset():

    assets = Asset.objects.all()

    data = []

    for a in assets:

        data.append({
            "Domain": a.domain,
            "IP": a.ip_address,
            "TLS Version": a.tls_version,
            "Cipher": a.cipher_suite,
            "Key Type": a.key_type,
            "Key Size": a.key_size,
            "PQC Status": a.pqc_status,
            "Risk Score": a.risk_score,
            "Days to Expiry": a.days_to_expiry,
            "Scan Status": a.scan_status
        })

    return pd.DataFrame(data)


def export_csv():

    df = generate_dataset()

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=cbom_report.csv'

    df.to_csv(response, index=False)

    return response


def export_json():

    df = generate_dataset()

    response = HttpResponse(content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename=cbom_report.json'

    response.write(df.to_json(orient="records"))

    return response


def export_excel():

    df = generate_dataset()

    response = HttpResponse(content_type='application/vnd.ms-excel')
    response['Content-Disposition'] = 'attachment; filename=cbom_report.xlsx'

    df.to_excel(response, index=False)

    return response


def export_pdf():

    buffer = BytesIO()

    p = canvas.Canvas(buffer)

    assets = Asset.objects.all()

    y = 800

    for asset in assets:

        line = f"{asset.domain} | {asset.tls_version} | {asset.cipher_suite} | Risk {asset.risk_score}"

        p.drawString(30, y, line)

        y -= 20

        if y < 50:
            p.showPage()
            y = 800

    p.save()

    buffer.seek(0)

    return HttpResponse(buffer, content_type='application/pdf')
