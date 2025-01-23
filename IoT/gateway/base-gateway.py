from fastapi import FastAPI, Request
import logging
import requests
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/logs/gateway.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Gateway")

# Métricas
requests_received = Counter('requests_received_total', 'Total requests received')
requests_forwarded = Counter('requests_forwarded_total', 'Total requests forwarded')

CLOUD_URL = "http://cloud:8001/store"

app = FastAPI()

@app.post("/data")
async def receive_data(request: Request):
    data = await request.json()
    logger.info(f"Received data: {data}")
    try:
        response = requests.post(CLOUD_URL, json=data)
        requests_forwarded.inc()
        logger.info(f"Data forwarded to cloud: {data}, Response: {response.status_code}")
        return {"status": "forwarded", "response_code": response.status_code}
    except Exception as e:
        logger.error(f"Error forwarding data to cloud: {e}")
        return {"status": "error", "message": str(e)}, 500

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Prometheus metrics server on port 8010")
    start_http_server(8010, addr="0.0.0.0")
    logger.info("Gateway service started")
    uvicorn.run(app, host="0.0.0.0", port=8000)
