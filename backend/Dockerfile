FROM zeek/zeek:latest

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:/usr/local/zeek/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/zeek/lib"

WORKDIR /app/backend

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential \
      libpcap-dev \
      python3-dev \
      python3-pip \
      python3-venv \
      tcpdump \
      tshark \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY ml-services/anomaly-engine /app/ml-services/anomaly-engine

ENV PYTHONPATH="/app/ml-services/anomaly-engine:${PYTHONPATH}"

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
