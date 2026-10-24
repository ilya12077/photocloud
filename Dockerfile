# Photocloud — образ для сервера (Home Assistant / Portainer).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PHOTOCLOUD_DOCKER=1 \
    STORAGE=smb DATA_DIR=/data BIND=0.0.0.0 PORT=8099 COOKIE_SECURE=true

# системный ffmpeg (эскизы видео, перекодирование) и база часовых поясов
RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg tzdata ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# imageio-ffmpeg в контейнере не нужен — есть системный ffmpeg
RUN grep -v '^imageio-ffmpeg' requirements.txt > /tmp/req.txt \
 && pip install -r /tmp/req.txt && rm /tmp/req.txt

COPY app ./app

# Версия сборки — файлом внутри образа (видна в «Обзоре» админки и в логе при старте).
# Не переменной окружения: Portainer при «Pull and redeploy» сохраняет старые переменные
# контейнера, и версия застревала на той, с которой контейнер создали.
COPY VERSION ./VERSION
ARG VERSION=dev
LABEL org.opencontainers.image.version=$VERSION

# непривилегированный пользователь; писать можно только в /data
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin photocloud \
 && mkdir -p /data && chown photocloud:photocloud /data
USER photocloud
VOLUME ["/data"]
EXPOSE 8099

# любой HTTP-ответ (в т.ч. 403 «только через прокси») значит, что сервер жив
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-m", "app.health"]

CMD ["python", "-m", "app"]
