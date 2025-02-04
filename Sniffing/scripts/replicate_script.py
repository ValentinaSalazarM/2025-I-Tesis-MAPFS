import os
import json
import time
import socket
import logging
import base64
from datetime import datetime


# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/replicate.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Sniffer-Replicate")

# Configuración
SHARED_DIR = "/shared_data"
PROCESSED_DIR = os.path.join(SHARED_DIR, "processed")
POLL_INTERVAL = 120  # Segundos entre verificaciones de nuevos archivos
MIN_FILE_SIZE = 1024

def find_analysis_files():
    """Busca archivos de análisis no procesados"""
        # Lista de archivos que cumplen con los criterios
    valid_files = [
        f for f in os.listdir(SHARED_DIR)
        if f.endswith(".analysis.json") and 
           os.path.getsize(os.path.join(SHARED_DIR, f)) > MIN_FILE_SIZE
    ]
    
    # Ordenar por fecha de modificación (más antiguos primero)
    return sorted(
        valid_files,
        key=lambda x: os.path.getmtime(os.path.join(SHARED_DIR, x))
    )


def process_analysis(file_path):
    """Replica la comunicación exactamente en el orden registrado en el análisis"""
    try:
        with open(file_path) as f:
            analysis = json.load(f)

        comms = analysis.get("comms", {})
        device_gateway = comms.get("device->gateway", [])
        
        if not device_gateway:
            logger.warning("No se encontraron comunicaciones device->gateway")
            return False

        logger.info(f"device_gateway = {device_gateway}")
        
        # Ordenar comunicaciones por timestamp
        sorted_comms = device_gateway
        logger.info(f"sorted_comms = {sorted_comms}")

        # Obtener configuración de conexión del primer paquete
        first_comm = sorted_comms[0]
        gateway_host = "mapfs-gateway"
        gateway_port = first_comm.get("dst_port")
        

        # Replicación fiel de la secuencia
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(15)
            try:
                logger.info(f"Conectando a {gateway_host}:{gateway_port}")
                s.connect((gateway_host, gateway_port))
                last_response = None

                for idx, comm in enumerate(sorted_comms, 1):
                    payload = comm.get("payload", {})

                    # Enviar mensaje tal como fue capturado
                    logger.info(
                        f"[Paso {idx}] Enviando payload: {json.dumps(payload, default=str)}"
                    )
                    s.sendall(json.dumps(payload).encode())

                    # Recibir respuesta
                    response = s.recv(4096)
                    if not response:
                        logger.error(f"[Paso {idx}] Sin respuesta del servidor")
                        return False

                    last_response = json.loads(response.decode())
                    logger.info(
                        f"[Paso {idx}] Respuesta recibida: {json.dumps(last_response, default=str)}"
                    )

                    # Pequeña pausa entre pasos
                    time.sleep(0.5)

                # Verificar última respuesta
                if last_response and last_response.get("status") == "success":
                    logger.info("Réplica completada exitosamente")
                    return True

                logger.error("La réplica no finalizó correctamente")
                return False

            except socket.timeout:
                logger.error("Timeout en la comunicación con el Gateway")
                return False
            except Exception as e:
                logger.error(f"Error durante la réplica: {str(e)}")
                return False

    except Exception as e:
        logger.error(f"Error procesando archivo: {str(e)}")
        return False


def main_loop():
    """Bucle principal de ejecución"""
    logger.info("Iniciando servicio de replicación.")

    while True:
        try:
            # Buscar nuevos archivos de análisis
            for fname in find_analysis_files():
                full_path = os.path.join(SHARED_DIR, fname)

                logger.info(f"Procesando archivo: {fname}")
                if process_analysis(full_path):
                    # Mover a procesados
                    new_path = os.path.join(PROCESSED_DIR, fname)
                    os.rename(full_path, new_path)
                    logger.info(f"Archivo procesado: {fname}")
                else:
                    logger.warning(f"Error procesando archivo: {fname}")

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            logger.info("Deteniendo servicio.")
            break
        except Exception as e:
            logger.error(f"Error en bucle principal: {str(e)}")
            time.sleep(30)


if __name__ == "__main__":
    # Verificar y crear directorios necesarios
    os.makedirs(SHARED_DIR, exist_ok=True)
    main_loop()
