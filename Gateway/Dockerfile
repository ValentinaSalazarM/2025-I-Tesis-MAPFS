FROM python:3.9-slim
WORKDIR /app
COPY gateway.py .
RUN pip install fastapi uvicorn requests prometheus_client
RUN mkdir /logs && chmod 777 /logs
CMD ["python", "gateway.py"]