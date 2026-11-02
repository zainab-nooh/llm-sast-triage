# SAST Triage web app in one container: Python, Semgrep, Bandit, git and the offline Semgrep rules.
# Your API key is NOT in the image: it is passed at run time from .env (see compose.yaml / README).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
# git: only for scanning public GitHub links
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# The app runs as a normal user, not root
RUN useradd --create-home --uid 10001 triage && mkdir -p /app/runs /scan && chown triage /app/runs
COPY --chown=root:root . .
USER triage
# Semgrep writes a small log and cache under HOME; /tmp is the one writable place besides /app/runs
ENV HOME=/tmp

EXPOSE 8765
# Inside the container the app must listen on all interfaces so Docker can forward the port.
# compose.yaml publishes it on 127.0.0.1 only, so it is still reachable from this computer alone.
ENTRYPOINT ["python", "-m", "codereview"]
CMD ["serve", "--host", "0.0.0.0", "--no-browser"]
