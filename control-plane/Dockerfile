FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

# nuclei is optional so the image still builds offline or on arm; pinned when it is pulled
ARG INSTALL_NUCLEI=true
ARG NUCLEI_VERSION=3.3.7
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && if [ "$INSTALL_NUCLEI" = "true" ] && [ "$(dpkg --print-architecture)" = "amd64" ]; then \
      curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
      && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin && rm /tmp/nuclei.zip; \
    fi \
 && apt-get purge -y curl unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY nuclei-templates ./nuclei-templates
# dashboard lives at the repo root; compose passes it in as a named build context
COPY --from=dashboard . /dashboard

RUN useradd --create-home aeroscan && mkdir -p /data && chown -R aeroscan /srv /data
USER aeroscan

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
