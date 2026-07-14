FROM python:3.13-slim-bookworm@sha256:de89ed8283721548f7f9c8acfd19d638f435fa3870693a017890e94be5d37fc6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/ml-services/anomaly-engine \
    NETRA_STORAGE_ROOT=/var/lib/netra/storage

WORKDIR /app/backend

# Netra executes no Perl. Debian's essential perl-base currently ships a
# vulnerable optional Socket XS module, so the module is removed and asserted.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      libpcap0.8 \
      tcpdump \
      tshark \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 netra \
    && useradd --uid 10001 --gid netra --create-home --shell /usr/sbin/nologin netra \
    && rm -f /usr/lib/x86_64-linux-gnu/perl-base/Socket.pm \
             /usr/lib/x86_64-linux-gnu/perl-base/auto/Socket/Socket.so \
    && ! perl -MSocket -e 1

COPY backend/requirements.txt /app/backend/requirements.txt
RUN python -m pip install --upgrade "pip==26.1.1" \
    && python -m pip install -r /app/backend/requirements.txt

COPY --chown=netra:netra backend /app/backend
COPY --chown=netra:netra ml-services/anomaly-engine /app/ml-services/anomaly-engine

RUN mkdir -p /var/lib/netra/storage \
    && chown -R netra:netra /var/lib/netra /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/api/health', timeout=3)" || exit 1

CMD ["sh", "-c", "if [ \"${NETRA_SERVICE_KIND:-api}\" = \"worker\" ]; then exec python manage.py run_postgres_worker; else exec gunicorn config.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers ${GUNICORN_WORKERS:-2} --threads ${GUNICORN_THREADS:-2} --timeout ${GUNICORN_TIMEOUT:-180} --access-logfile - --error-logfile -; fi"]
