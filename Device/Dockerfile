FROM python:3.9-slim
WORKDIR /app
COPY device.py .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir /logs && chmod 777 /logs 
CMD ["python", "device.py"]