# FairRun public demo: MOCK ONLY. No Airwallex or Anthropic keys go into this image.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY fairrun ./fairrun
COPY scenarios ./scenarios
COPY dashboard ./dashboard
COPY .streamlit ./.streamlit
RUN useradd -m app && chown -R app /app
USER app
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1
CMD ["streamlit","run","dashboard/app.py","--server.port=8501","--server.address=0.0.0.0","--server.headless=true","--browser.gatherUsageStats=false"]
