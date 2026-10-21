"""Проверка живости для Docker HEALTHCHECK: любой HTTP-ответ = сервер работает."""
import os
import sys
import urllib.error
import urllib.request

url = f"http://127.0.0.1:{os.environ.get('PORT', '8099')}/static/style.css"
try:
    urllib.request.urlopen(url, timeout=4)
except urllib.error.HTTPError:
    pass                      # 403 «только через прокси» — тоже ответ
except Exception:  # noqa: BLE001
    sys.exit(1)
