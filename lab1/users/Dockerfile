FROM ubuntu

WORKDIR /app

RUN apt update && \
    apt install -y python3 python3-pip openssl libengine-gost-openssl1.1 && \
    apt clean
COPY requirements.txt .
RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
