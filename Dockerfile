FROM python:3.12-slim

# Fixed numeric UID/GID (not just a name) so this lines up with
# runAsUser/runAsGroup/fsGroup in the k8s manifests and docker-compose's
# `user:` overrides without needing to look anything up at deploy time.
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY aws_emulator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aws_emulator/ .

ENV SERVICE_MODE=all \
    PORT=4566 \
    S3_DATA_DIR=/data/objects \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# The app only ever writes here (S3 object bytes) - everything else (/app)
# stays read-only at runtime, which is what lets the compose/k8s manifests
# set readOnlyRootFilesystem: true.
RUN mkdir -p /data/objects && chown -R appuser:appuser /data/objects

USER appuser

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
