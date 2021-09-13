
import requests

from organizations.models import Organization
from cves.models import Product
from .custom_alert_config import TELEGRAM_CHAT_ID, TELEGRAM_TOKEN_NEW_VULN, TELEGRAM_TOKEN_UPDATE_VULN
from .custom_alert_config import YOU_TRACK_TOKEN, YOU_TRACK_PROJECT_ID, YOU_TRACK_BASE_URL


def vuln_product_monitoring_check(vuln):
    for org in Organization.objects.filter(is_active=True):
        for product_name in vuln.vulnerable_products:
            product_name = product_name.split(":")
            product_name = product_name[4]
            product = Product.objects.filter(name=product_name).first()
            if product and product.is_monitored(org):
                return product_name
        return False



def custom_alert_to_telegram(event_type, vuln):
    if event_type == "new_vuln":
        message = "Новая уязвимость для {}\n"
        alert_token = TELEGRAM_TOKEN_NEW_VULN
    if event_type == "update_vuln":
        message = "Изменились данные для уязвимости {}\n"
        alert_token = TELEGRAM_TOKEN_UPDATE_VULN

    vulnerable_product = vuln_product_monitoring_check(vuln)
    if vulnerable_product:
        messgae = message.format(vulnerable_product)
        message += "\nCVE-ID: {}\n Описание: {}\n".format(vuln.cve_id, vuln.summary)
        message += "CVSS Score: {}\n CVSS Вектор: {}\n ".format(str(vuln.cvss), str(vuln.cvss_vector))
        message += "CVSS3 Score: {}\n CVSS3 Вектор: {}\n ".format(str(vuln.cvss3), str(vuln.cvss3_vector))
        messgae += "Данные по уязвимым продуктам: {}\n".format(str(vuln.vulnerable_products))
        message += "Ссылки: {}".format(str(vuln.reflinks))

        URL = "https://api.telegram.org/bot{}/".format(alert_token)
        URL += "sendMessage?chat_id={}&text={}".format(TELEGRAM_CHAT_ID, message)
        r = requests.get(URL)


def custom_alert_to_you_track(event_type, vuln):
    if event_type == "new_vuln":
        issue_header = "Обнаружена новая уязвимость! {}".format(vuln.cveid)
    if event_type == "update_vuln":
        issue_header = "Обнаружены изменения в уязвимости {}".format(vuln.cveid)

    vulnerable_product = vuln_product_monitoring_check(vuln)

    if vulnerable_product:
#       message = "<h1>Идентификатор уязвимости</h1>CVE-ID:  {}".format(vuln.cve_id)
        message = "<h1>Описание</h1>{}".format(vuln.summary)
#       message += "<h1>Дата выявления системой Patrowl<h1>{}".format(str(vuln.modified))
        message += "<h1>Дата публикации</h1>{}".format(str(vuln.published))
        message += "<h1>Данные по уязвимым продуктам</h1>{}".format(str(vuln.vulnerable_products))
        message += "<h1>CVSS</h1>CVSS Score: {}, CVSS Вектор: {}".format(str(vuln.cvss), str(vuln.cvss_vector))
        message += "<h1>CVSSv3</h1>CVSSv3 Score {}, CVSSv3 Вектор: {}".format(str(vuln.cvss3), str(vuln.cvss3_vector))
        message += "<h1>Источники</h1>{}".format(str(vuln.reflinks))

        URL = YOU_TRACK_BASE_URL + "/issues"
        headers = {
            "Accept":"application/json",
            "Authorization":"Bearer {}".format(YOU_TRACK_TOKEN),
            "Content-Type":"application/json"
        }

        request_payload = {
            "project" : {
                "id" : YOU_TRACK_PROJECT_ID
            },
            "summary" : issue_header,
            "description" : message
        }

        r = requests.post(URL, headers=headers, json=request_payload)
        print(r.json())






def send_alert(end_system, event_type, vuln):
    if end_system == "telegram":
        custom_alert_to_telegram(event_type, vuln)
    else:
        custom_alert_to_you_track(event_type, vuln)
