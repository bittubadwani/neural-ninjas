from django.urls import path
from .views import (
    scan_asset,
    batch_scan,
    asset_inventory,
    cbom_view,
    pqc_posture,
    reporting_page,
    generate_report
)

from .views import dashboard
urlpatterns = [

    # ---------------------------
    # Scanning
    # ---------------------------
    path('', scan_asset, name='scan'),
    path('scan/', scan_asset, name='scan_asset'),

    # Batch scanning
    path('batch-scan/', batch_scan, name='batch_scan'),

    # ---------------------------
    # Inventory / CBOM
    # ---------------------------
    path('assets/', asset_inventory, name='assets'),
    path('cbom/', cbom_view, name='cbom'),

    # ---------------------------
    # Analytics
    # ---------------------------
    path('pqc-posture/', pqc_posture, name='pqc_posture'),

    path('dashboard/', dashboard, name='dashboard'),
    
    # ---------------------------
    # Analytics
    # ---------------------------
    path('reporting/', reporting_page, name='reporting'),

    path('generate-report/', generate_report, name='generate_report'),

]
