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

# EC2/VPC state is an in-memory Python singleton (see ec2_backend.py) - it
# was designed to be single-process, not just single-container. gunicorn
# workers are separate OS processes with independent memory, so any mode
# that serves EC2/VPC (ec2, all) MUST run with exactly one worker, or a
# CreateSubnet handled by worker 1 becomes invisible to a DescribeSubnets
# routed to worker 2. Only `s3` mode is fully stateless (Postgres + shared
# volume) and safe to run with multiple workers per container.
CMD ["sh", "-c", "if [ \"$SERVICE_MODE\" = \"s3\" ]; then WORKERS=4; else WORKERS=1; fi; exec gunicorn --bind 0.0.0.0:${PORT} --workers $WORKERS --threads 2 --access-logfile - wsgi:app"]
