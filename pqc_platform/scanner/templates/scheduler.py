import time
from .reporting import export_csv


def scheduled_report():

    while True:

        export_csv()

        time.sleep(86400)
