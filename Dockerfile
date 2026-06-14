# syntax=docker/dockerfile:1

# ---- stage 1: fetch only the SecLists slices ffuf/arjun need (keeps image small) ----
FROM kalilinux/kali-rolling AS wordlists
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --filter=blob:none --sparse \
      https://github.com/danielmiessler/SecLists.git /opt/seclists \
 && cd /opt/seclists \
 && git sparse-checkout set Discovery/Web-Content Discovery/DNS

# ---- stage 2: final runtime image ----
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/home/mcpbot \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap ffuf nuclei arjun \
      python3 python3-pip python3-venv \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Bake nuclei templates at build time so the read-only runtime never needs to update them.
RUN nuclei -update-templates -update-template-dir /opt/nuclei-templates -disable-update-check || true

COPY --from=wordlists /opt/seclists /opt/seclists

# Python deps in a venv (PEP 668: kali's system python is externally managed).
COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

COPY server.py /app/server.py

# Non-root identity (UID 1000), per SPECS.md §2.
RUN useradd -m -u 1000 -s /usr/sbin/nologin mcpbot
USER 1000
WORKDIR /app

EXPOSE 8000
CMD ["python", "/app/server.py"]
