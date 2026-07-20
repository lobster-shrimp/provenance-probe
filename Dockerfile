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
CMD ["provenance-probe","serve","--host","0.0.0.0","--port","8770"]
