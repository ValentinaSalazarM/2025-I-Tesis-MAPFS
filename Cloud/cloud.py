from fastapi import FastAPI, Request
import logging
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/logs/cloud.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Cloud")

# Métricas
data_stored_total = Counter('data_stored_total', 'Total data entries stored')

app = FastAPI()
data_store = []

@app.post("/store")
async def store_data(request: Request):
    data = await request.json()
    data_stored_total.inc()
    data_store.append(data)
    logger.info(f"Data stored: {data}")
    return {"status": "stored", "data_count": len(data_store)}

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Prometheus metrics server on port 8011")
    start_http_server(8011)
    logger.info("Cloud service started")
    uvicorn.run(app, host="0.0.0.0", port=8001)
