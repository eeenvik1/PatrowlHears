import requests


def custom_alert_to_telegram(event_type, vuln):
    pass


def custom_alert_to_you_track(evnt_type, vuln):
    pass



def custom_alert(end_system, event_type, vuln):
    if end_system == "telegram":
        custom_alert_to_telegram(event_type, vuln)
    else:
        custom_alert_to_you_track(event_type, vuln)