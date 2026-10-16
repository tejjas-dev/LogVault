FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# run as non-root; /app/instance holds the SQLite DB (and local-dev bucket)
RUN useradd -m logvault && mkdir -p /app/instance && chown -R logvault /app/instance
USER logvault
EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--timeout", "120", "app:app"]
