FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --only-upgrade zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi==0.163.2 \
    starlette==1.10.0 \
    "uvicorn[standard]==0.54.0" \
    "psycopg[binary]==3.2.3"

COPY main.py .

EXPOSE 8081

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8081"]
