import subprocess
from scapy.all import IP, TCP, rdpcap
from datetime import datetime

import binascii
import logging
import socket
import base64
import time
import json
import os


# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/capture.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Sniffer-Capture")

# Configuración
SHARED_DIR = "/shared_data"
CAPTURE_INTERVAL = 60  
MIN_FILE_SIZE = 2048

def analyze_pcap(pcap_file):
    """Analiza un archivo pcap y genera metadatos estructurados"""

    analysis = {"ip_role_mapping": {}, "comms": {}}
    try:
        packets = rdpcap(pcap_file)

        for pkt in packets:
            if not IP in pkt or not TCP in pkt:
                continue
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            payload = bytes(pkt[TCP].payload).decode(errors="ignore")
            dst_port = pkt[TCP].dport

            # Parseo básico del payload
            try:
                payload_data = json.loads(payload)
            except json.JSONDecodeError:
                payload_data = payload  # Si no es JSON, guardar como texto

            # Actualizar mapeo de roles según operación
            if payload_data and isinstance(payload_data, dict):
                operation = payload_data.get("operation", "")
                logger.info(f"payload_data={payload_data}")
                # Registro de dispositivo
                if operation == "register_device":
                    analysis["ip_role_mapping"].update(
                        {src_ip: "device", dst_ip: "cloud"}
                    )
                # Registro de Gateway
                elif operation == "register_gateway":
                    analysis["ip_role_mapping"].update(
                        {src_ip: "gateway", dst_ip: "cloud"}
                    )

                if operation != "" and not operation.startswith("register"):
                    # Procesar payload
                    parsed_payload = {}
                    for key, value in payload_data.items():
                        # Convertir a entero si es posible
                        if isinstance(value, str) and value.isdigit():
                            parsed_payload[key] = int(value)
                        elif isinstance(value, dict):
                            # Convertir valores dentro de diccionarios anidados
                            parsed_payload[key] = {
                                k: (int(v) if isinstance(v, str) and v.isdigit() else v)
                                for k, v in value.items()
                            }
                        else:
                            parsed_payload[key] = value

                    entry = {
                        "timestamp": datetime.fromtimestamp(pkt.time).isoformat(),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "payload": parsed_payload,
                    }

                    # Almacenar en estructuras
                    leng = len(analysis["comms"]) > 0
                    logger.info(f"entry = {entry} y leng = {leng}")
                    if not len(analysis["comms"]) > 0:
                        temp = analysis["ip_role_mapping"]
                        logger.info(f"ip_role_mapping = {temp}")

                        analysis["ip_role_mapping"].update(
                            {src_ip: "device", dst_ip: "gateway"}
                        )
                        temp = analysis["ip_role_mapping"]
                        logger.info(f"DESPUÉS: ip_role_mapping = {temp}")
                    
                    # Determinar nombres basados en el mapeo
                    src_role = analysis["ip_role_mapping"].get(src_ip, src_ip)
                    dst_role = analysis["ip_role_mapping"].get(dst_ip, dst_ip)
                    
                    if src_role == "gateway" and dst_role != "device":
                        dst_role = "cloud"
                        analysis["ip_role_mapping"].update(
                            {dst_ip: "cloud"}
                        )
                    # Construir estructura de datos
                    comm_key = f"{src_role}->{dst_role}"
                    
                    if comm_key not in analysis["comms"]:
                        analysis["comms"][comm_key] = []

                    analysis["comms"][comm_key].append(entry)

        analysis["comms"] = process_intercepted_data(analysis["comms"])
        # Guardar análisis
        analysis_file = f"{pcap_file}.analysis.json"
        with open(analysis_file, "w") as f:
            json.dump(analysis, f, indent=2)
        logger.info(f"Análisis guardado en {analysis_file}")
        return True

    except Exception as e:
        logger.error(f"Error analizando {pcap_file}: {str(e)}")
        return False


def process_intercepted_data(intercepted_data):
    """Elimina diccionarios duplicados de una lista comparándolos con '=='."""

    def remove_duplicates(dictionaries_list):
        unique_list = []
        for dic in dictionaries_list:
            if dic not in unique_list:
                unique_list.append(dic)
        return unique_list

    # Recorremos cada llave en "comms" y eliminamos los duplicados en cada lista
    for key, messages in intercepted_data.items():
        intercepted_data[key] = remove_duplicates(messages)
    return intercepted_data


def capture_loop():
    """Bucle principal de captura y análisis"""
    while True:
        try:
            # Generar nombre de archivo con timestamp
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            pcap_file = f"{SHARED_DIR}/capture_{timestamp}.pcap"

            # Iniciar captura con timeout
            logger.info(f"Iniciando captura: {pcap_file}")
            tcpdump = subprocess.Popen(
                ["tcpdump", "-i", "any", "-w", pcap_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Esperar intervalo de captura
            time.sleep(CAPTURE_INTERVAL)

            # Detener captura
            tcpdump.terminate()
            tcpdump.wait()
            logger.info(f"Captura finalizada: {pcap_file}")

            # Analizar captura
            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > MIN_FILE_SIZE:
                if analyze_pcap(pcap_file):
                    os.rename(pcap_file, f"{pcap_file}.processed")
                else:
                    os.rename(pcap_file, f"{pcap_file}.error")
            else:
                logger.warning("Captura vacía o no creada, reintentando...")
                os.remove(pcap_file) if os.path.exists(pcap_file) else None

        except Exception as e:
            logger.error(f"Error en bucle de captura: {str(e)}")
            time.sleep(10)


if __name__ == "__main__":
    # Verificar y crear directorios necesarios
    os.makedirs(SHARED_DIR, exist_ok=True)
    capture_loop()
