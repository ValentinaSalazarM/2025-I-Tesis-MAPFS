FROM python:3.9-slim
WORKDIR /app
COPY cloud.py .
RUN pip install fastapi uvicorn prometheus_client
RUN mkdir /logs && chmod 777 /logs
CMD ["python", "cloud.py"]