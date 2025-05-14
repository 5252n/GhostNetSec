import requests

TOKEN = "7366831152:AAF5Ax-OWmIvwEO2PsKnAFsyfTRw_aY-fqc"
CHAT_ID = "25166548"

def send_telegram(msg):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": msg}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"❌ Error sending telegram message: {e}")
