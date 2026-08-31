FROM python:3.12-slim

WORKDIR /app

COPY aws_emulator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aws_emulator/ .

ENV SERVICE_MODE=all \
    PORT=4566 \
    S3_DATA_DIR=/data/objects \
    PYTHONUNBUFFERED=1

EXPOSE 4566
VOLUME ["/data/objects"]

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 4 --threads 2 --access-logfile - wsgi:app"]
