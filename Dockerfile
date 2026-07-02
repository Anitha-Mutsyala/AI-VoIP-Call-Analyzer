FROM python:3.12-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 10000

CMD ["gunicorn", "--bind", "0.0.0.0:10000", "--timeout", "300", "app:app"]