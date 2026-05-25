FROM python:3.12-slim

LABEL org.opencontainers.image.title="OpenVAS Mock Scanner"
LABEL org.opencontainers.image.description="Deterministic OpenVAS scanner compatibility mock for gvmd integration tests"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MOCK_HOST=0.0.0.0 \
    MOCK_PORT=8080

WORKDIR /app

RUN groupadd --system mockscanner \
    && useradd --system --gid mockscanner --home-dir /nonexistent --shell /usr/sbin/nologin mockscanner

COPY openvas_mock_scanner ./openvas_mock_scanner
COPY README.md LICENSE ./

USER mockscanner

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import json, os, urllib.request; url='http://127.0.0.1:%s/health' % os.environ.get('MOCK_PORT', '8080'); data=json.load(urllib.request.urlopen(url, timeout=2)); raise SystemExit(0 if data.get('status') == 'ok' else 1)"

CMD ["python", "-m", "openvas_mock_scanner"]
