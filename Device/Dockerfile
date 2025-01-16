FROM python:3.9-slim
WORKDIR /app
COPY device.py .
RUN pip install requests prometheus_client
RUN mkdir /logs && chmod 777 /logs 
CMD ["python", "device.py"]