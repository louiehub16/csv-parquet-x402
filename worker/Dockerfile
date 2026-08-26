# x402 Parquet Engine container (RunPod serverless CPU).
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pyarrow boto3 python-multipart

COPY main.py .

EXPOSE 8000
# workers=1: the streaming writer holds per-process state; RunPod scales by
# spawning replicas, not uvicorn workers. Multiple workers would split or
# corrupt in-flight multipart upload state.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
