import logging
import time
import requests
import random

# Métricas
from prometheus_client import start_http_server, Counter, Histogram


# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/logs/device.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Device")

# Métricas
data_sent_total = Counter('data_sent_total', 'Total data packets sent')
send_latency = Histogram('send_latency_seconds', 'Latency of data sending')

GATEWAY_URL = "http://gateway:8000/data"

def send_data():
    while True:
        sensor_data = {"temperature": random.uniform(20.0, 30.0), "humidity": random.uniform(50, 70)}
        start_time = time.time()
        try:
            response = requests.post(GATEWAY_URL, json=sensor_data)
            data_sent_total.inc()
            send_latency.observe(time.time() - start_time)
            logger.info(f"Data sent: {sensor_data}, Response: {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending data: {e}")
        time.sleep(25)

if __name__ == "__main__":
    logger.info("Starting Prometheus metrics server on port 8012")
    start_http_server(8012)
    logger.info("Device service started")
    send_data()
