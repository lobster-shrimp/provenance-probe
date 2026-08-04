FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY provenance_probe ./provenance_probe
RUN pip install --no-cache-dir -e .
# Reference tokenizers are NOT baked in; the image stays small and you control
# which model weights metadata is pulled. Build them at first run:
#   docker exec -it <c> provenance-probe build-reference
EXPOSE 8770
ENV PROVENANCE_PROBE_HOME=/data
VOLUME /data
# Shell form so $PORT (set by Render/HF/Cloud Run/etc.) is honored; falls back
# to 8770 for local `docker run`. Public-hosting gates (SSRF egress guard +
# basic auth) are opt-in via env vars — see deploy/hf-space/README.md.
CMD provenance-probe serve --host 0.0.0.0 --port ${PORT:-8770}
