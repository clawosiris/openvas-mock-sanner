FROM python:3.12-slim

LABEL org.opencontainers.image.title="OpenVAS Mock Scanner"
LABEL org.opencontainers.image.description="Deterministic OpenVAS scanner compatibility mock for gvmd integration tests"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LISTENING=0.0.0.0:80

WORKDIR /app

RUN groupadd --system mockscanner \
    && useradd --system --gid mockscanner --home-dir /nonexistent --shell /usr/sbin/nologin mockscanner \
    && apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap 'cap_net_bind_service=+ep' "$(readlink -f /usr/local/bin/python3)" \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY openvas_mock_scanner ./openvas_mock_scanner
COPY README.md LICENSE ./

USER mockscanner

EXPOSE 80 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import json, os, urllib.request; port=os.environ.get('MOCK_PORT') or os.environ.get('LISTENING','127.0.0.1:80').rsplit(':',1)[1]; data=json.load(urllib.request.urlopen('http://127.0.0.1:%s/health/alive' % port, timeout=2)); raise SystemExit(0 if data.get('status') == 'ok' else 1)"

CMD ["python", "-m", "openvas_mock_scanner"]
