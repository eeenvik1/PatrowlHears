import requests

from backend_app.vulns.models import Vuln
from organizations.models import Organization
from cves.models import Product
from custom_alert_config import TELEGRAM_CHAT_ID, TELEGRAM_TOKEN_NEW_VULN, TELEGRAM_TOKEN_UPDATE_VULN


def vulnreable_product_by_vuln(vuln):
    for org in Organization.objects.filter(is_active=True):
        for product_name in vuln.vulnerable_products:
            product_name = product_name.split(":")
            product_name = product_name[4]
            product = Product.objects.filter(name=product_name).first()
            if product and product.id_monitored(org):
                return product_name
        return False



def custom_alert_to_telegram(event_type, vuln_id):
    if event_type == "new_vuln":
        message = "Новая уязвимость для {}\n"
        alert_token = TELEGRAM_TOKEN_NEW_VULN
    if event_type == "update_vuln":
        message = "Изменились данные для уязвимости {}\n"
        alert_token = TELEGRAM_TOKEN_UPDATE_VULN

    vuln = Vuln.objects.filter(id=vuln_id).first()
    if vuln:
        vulnerable_product = vulnreable_product_by_vuln(vuln)
        if vulnerable_product:
            messgae = message.format(vulnerable_product)
            message = "\nCVE-ID: {}\n Описание: {}\n".format(vuln.cve_id, vuln.summary)
            message += "CVSS Score: {}\n CVSS Вектор: {}\n ".format(str(vuln.cvss), str(vuln.cvss_vector))
            message += "CVSS3 Score: {}\n CVSS3 Вектор: {}\n ".format(str(vuln.cvss3), str(vuln.cvss3_vector))
            messgae += "Данные по уязвимым продуктам: {}\n".format(str(vuln.vulnerable_products))
            message += "Ссылки: {}".format(str(vuln.reflinks))

            URL = "https://api.telegram.org/bot{}/".format(alert_token)
            URL += "sendMessage?chat_id={}&text={}".format(TELEGRAM_CHAT_ID, message)
            r = requests.get(URL)

def custom_alert_to_you_track(evnt_type, vuln_id):
    pass



def custom_alert(end_system, event_type, vuln_id):
    if end_system == "telegram":
        custom_alert_to_telegram(event_type, vuln)
    else:
        custom_alert_to_you_track(event_type, vuln)