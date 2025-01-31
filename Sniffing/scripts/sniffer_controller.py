import subprocess
import docker
import time
from scapy.all import *
from scapy.layers.inet import TCP, IP
import json
from datetime import datetime
import logging

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/sniffer.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Sniffer")

# Configuración
PCAP_DIR = "/captures"
TARGET_MESSAGE = "[AUTH] Autenticación mutua"
CONTAINER_NAMES = ["mapfs-cloud", "mapfs-gateway", "mapfs-device"]

def get_container_ips():
    """Obtiene las IPs de los contenedores desde Docker"""
    client = docker.from_env()
    ips = {}
    
    try:
        for container in client.containers.list():
            if container.name in CONTAINER_NAMES:
                # Obtener la IP de la red bridge específica
                networks = container.attrs["NetworkSettings"]["Networks"]
                if "mapfs_network" in networks:  # Nombre de tu red en docker-compose
                    ips[container.name] = networks["mapfs_network"]["IPAddress"]
                logger.info(f"[Container IP]: Contenedor {name} con IP: {ips[name]}")
    except Exception as e:
        logger.error(f"Error obteniendo IPs: {str(e)}")
    
    return ips

def monitor_logs_for_message():
    """Monitorea logs usando la API de Docker con timeout ajustado"""
    client = docker.from_env()
    start_time = time.time()
    
    while time.time() - start_time < 60:  # Timeout de 60 segundos
        try:
            for container in client.containers.list():
                if container.name in CONTAINER_NAMES:
                    logs = container.logs(since=int(start_time)).decode("utf-8")
                    if TARGET_MESSAGE in logs:
                        logger.info(f"Mensaje detectado en {container.name}")
                        return True
            time.sleep(2)
        except Exception as e:
            logger.info(f"Error monitoreando logs: {str(e)}")
            time.sleep(5)
    return False

def capture_and_analyze():
    # 1. Obtener IPs de los contenedores
    container_ips = get_container_ips()
    logger.info("IPs detectadas:", container_ips)
    
    if not container_ips:
        raise RuntimeError("No se pudieron obtener las IPs de los contenedores")

    # 2. Iniciar captura
    pcap_file = f"{PCAP_DIR}/capture_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap"
    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", "any", "-w", pcap_file, "port 5001"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # 3. Monitorear logs
    logger.info("Monitoreando logs...")
    if monitor_logs_for_message():
        logger.info("Mensaje final detectado, deteniendo captura...")
        tcpdump.terminate()
        tcpdump.wait(10)
        
        # 4. Analizar tráfico
        logger.info("\nReconstruyendo comunicación:")
        packets = rdpcap(pcap_file)
        
        comms = []
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Mapear IPs a nombres
                src_name = next((k for k, v in container_ips.items() if v == src_ip), src_ip)
                dst_name = next((k for k, v in container_ips.items() if v == dst_ip), dst_ip)
                
                payload = bytes(pkt[TCP].payload).decode(errors='ignore')
                try:
                    payload_data = json.loads(payload) if payload.strip() else None
                except:
                    payload_data = payload
                
                comms.append({
                    'timestamp': datetime.fromtimestamp(pkt.time).isoformat(),
                    'source': src_name,
                    'destination': dst_name,
                    'payload': payload_data
                })
        
        # Imprimir resultados
        for entry in comms[-5:]:  # Mostrar últimos 5 mensajes
            logger.info(f"[{entry['timestamp']}] {entry['source']} -> {entry['destination']}:")
            logger.info(json.dumps(entry['payload'], indent=2) if entry['payload'] else "<sin payload>")
    else:
        logger.info("Timeout: Mensaje final no detectado")
        tcpdump.terminate()

if __name__ == "__main__":
    while True:
        capture_and_analyze()