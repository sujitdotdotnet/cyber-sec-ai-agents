# SecAgents dashboard. Build: docker build -t secagents .   Run: docker run -p 8501:8501 --env-file .env secagents
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# runs as an unprivileged user; the writable data folders (Chroma index, history, memory, live logs) are created on demand
RUN useradd --create-home --uid 10001 app && chown -R app:app /app
USER app

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"
CMD ["streamlit", "run", "app/streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501"]
