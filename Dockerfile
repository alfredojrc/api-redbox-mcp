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
    PYTHONUNBUFFERED=1 \
    XDG_CONFIG_HOME=/tmp/.config
# nuclei/uncover insist on writing a config dir under XDG_CONFIG_HOME. Point it at
# /tmp, which is a writable tmpfs at runtime, so they work under the read-only rootfs.

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap ffuf nuclei arjun \
      python3 python3-pip python3-venv \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Bake nuclei templates at build time so the read-only runtime never needs to update them.
# Fail the build (no `|| true`) if the download produced no templates — shipping an
# empty template dir silently broke nuclei before.
RUN nuclei -update-templates -update-template-dir /opt/nuclei-templates \
 && test -n "$(find /opt/nuclei-templates -name '*.yaml' -print -quit)"
# nuclei creates the template dir mode 700 root:root; the runtime user (UID 1000)
# must be able to read it under the read-only rootfs.
RUN chmod -R a+rX /opt/nuclei-templates

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
