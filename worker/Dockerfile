# x402 Parquet Engine container (RunPod serverless CPU).
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pyarrow boto3 python-multipart

# R61: main.py imports s3_guard inside make_client. Copying only main.py made
# every conversion fail during preflight with ModuleNotFoundError, so the image
# must ship the guard module alongside it.
COPY main.py s3_guard.py ./

EXPOSE 8000
# workers=1: the streaming writer holds per-process state; RunPod scales by
# spawning replicas, not uvicorn workers. Multiple workers would split or
# corrupt in-flight multipart upload state.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
