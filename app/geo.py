"""Сведения о снимке для панели «Подробнее»: камера, размеры, место съёмки.

GPS и камера — из EXIF (JPEG — по началу файла, HEIC — через pillow-heif).
Адрес по координатам — OpenStreetMap Nominatim: не чаще раза в секунду (их правила),
с понятным User-Agent, результат навсегда кэшируется в SQLite — одно место
запрашивается один раз."""
from __future__ import annotations

import asyncio
import io
import logging
import time

import httpx
from PIL import Image

log = logging.getLogger("photocloud.geo")

NOMINATIM = "https://nominatim.openstreetmap.org/reverse"
UA = "photocloud/1 (self-hosted family photo archive)"


def _ratio(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError, ZeroDivisionError):
        return float("nan")


def _dms(vals, ref) -> float | None:
    try:
        d, m, s = (_ratio(x) for x in vals)
    except (TypeError, ValueError):
        return None
    v = d + m / 60 + s / 3600
    if v != v:                                   # NaN
        return None
    if isinstance(ref, bytes):
        ref = ref.decode("ascii", "ignore")
    return -v if str(ref).strip().upper() in ("S", "W") else v


def exif_info(data: bytes) -> dict:
    """{width, height, camera, lat, lon} — что нашлось. Битый файл -> {}."""
    out: dict = {}
    try:
        with Image.open(io.BytesIO(data)) as im:
            out["width"], out["height"] = im.size
            ex = im.getexif()
            if ex.get(274) in (5, 6, 7, 8):          # поворот на 90° — меняем местами
                out["width"], out["height"] = out["height"], out["width"]
            make, model = str(ex.get(0x010F) or "").strip(" \x00"), str(ex.get(0x0110) or "").strip(" \x00")
            if model:
                out["camera"] = model if make and make.split()[0].lower() in model.lower() else f"{make} {model}".strip()
            gps = ex.get_ifd(0x8825)
            if gps and 2 in gps and 4 in gps:
                lat, lon = _dms(gps[2], gps.get(1, "N")), _dms(gps[4], gps.get(3, "E"))
                if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180 \
                        and not (lat == 0 and lon == 0):
                    out["lat"], out["lon"] = round(lat, 6), round(lon, 6)
    except Exception:  # noqa: BLE001 — нет EXIF / не картинка — просто без подробностей
        pass
    return out


class Geocoder:
    def __init__(self, db):
        self.db = db
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(6.0), headers={"User-Agent": UA})
        self._mu = asyncio.Lock()
        self._last = 0.0

    async def close(self) -> None:
        await self._http.aclose()

    async def cached(self, lat: float, lon: float) -> str | None:
        """Адрес, если уже известен (без запроса в интернет); '' — места нет; None — не спрашивали."""
        return await asyncio.to_thread(self.db.geo_get, f"{lat:.4f},{lon:.4f}")

    async def address(self, lat: float, lon: float) -> str | None:
        key = f"{lat:.4f},{lon:.4f}"                 # ~10 м — соседние снимки делят запрос
        hit = await asyncio.to_thread(self.db.geo_get, key)
        if hit is not None:
            return hit or None
        async with self._mu:                         # Nominatim: не чаще раза в секунду
            hit = await asyncio.to_thread(self.db.geo_get, key)
            if hit is not None:
                return hit or None
            wait = 1.05 - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()
            try:
                r = await self._http.get(NOMINATIM, params={
                    "format": "jsonv2", "lat": f"{lat:.6f}", "lon": f"{lon:.6f}",
                    "zoom": 16, "accept-language": "ru", "addressdetails": 1})
                if r.status_code != 200:
                    log.info("адрес не получен: HTTP %s", r.status_code)
                    return None                      # не кэшируем — попробуем в другой раз
                addr = _short(r.json())
            except (httpx.HTTPError, ValueError) as e:
                log.info("адрес не получен: %s", type(e).__name__)
                return None
        await asyncio.to_thread(self.db.geo_put, key, addr)
        return addr or None


def _short(j: dict) -> str:
    """Коротко, как в галереях: «улица, город, область, страна» без индекса и мелочей."""
    a = j.get("address") or {}
    parts = []
    for k in ("road", "pedestrian", "neighbourhood", "suburb"):
        if a.get(k):
            parts.append(a[k]); break
    for k in ("city", "town", "village", "hamlet", "municipality"):
        if a.get(k):
            parts.append(a[k]); break
    for k in ("state", "region"):
        if a.get(k) and a[k] not in parts:
            parts.append(a[k]); break
    if a.get("country"):
        parts.append(a["country"])
    return ", ".join(parts) or str(j.get("display_name") or "")[:200]
