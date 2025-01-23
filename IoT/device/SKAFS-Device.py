import requests
import logging
import random
import socket
import json
import os

from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter, Histogram

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/logs/SKAFS-device.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Device")

# API expuesto para el CA
CA_URL = "http://skafs-cloud:8001"

# Configuración del socket
GATEWAY_HOST = 'skafs-gateway'  # Dirección IP del Gateway
GATEWAY_PORT = 5000         # Puerto del Gateway
gateway_socket = None

# Retos fijos para el circuito PUF
C_F0 = None
C_F1 = None

# Parámetros de registro
registration_parameters = {}

#######################################################
#              REGISTRO DISPOSITIVO IOT               #
#######################################################         
def registrationIoT():
    global registration_parameters, C_F0, C_F1
    
    # Generación de DPUF challenge y estado
    C_1 = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    state = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  

    # Generación de la identidad del IoT
    IoT_Identity = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  

    logger.info(f"IoT_Identity: {IoT_Identity}")
    
    # Paso 1: Recepción de desafíos desde el CA
    try:
        response = requests.get(f"{CA_URL}/registration/challenges")
        response.raise_for_status()
        challenges = response.json()
        C_F0 = challenges['C_F0']
        C_F1 = challenges['C_F1']
        logger.info("Desafíos recibidos del CA.")
    except requests.RequestException as e:
        logger.error(f"Error al recibir desafíos del CA: {e}")
        return
    
    # Cálculo de las funciones FPUF y DPUF
    FPUF_Fixed_F0 = FPUF(C_F0)
    FPUF_Fixed_F1 = FPUF(C_F1)
    DPUF_C1 = DPUF(C_1, state)

    # Paso 2: Envío de datos al CA
    try:
        payload = {
            "IoT_Identity": IoT_Identity,
            "DPUF_C1": DPUF_C1,
            "FPUF_Fixed_F0": FPUF_Fixed_F0,
            "FPUF_Fixed_F1": FPUF_Fixed_F1
        }
        response = requests.post(f"{CA_URL}/registration/device", json=payload)
        response.raise_for_status()
        response_data = response.json()
        CA_K_previous = response_data["CA_K_previous"]
        T_j = response_data["IoT_T_j"]
        logger.info("Datos enviados y respuesta recibida del CA.")
    except requests.RequestException as e:
        logger.error(f"Error al enviar datos al CA: {e}")
        return
    
    # Inicialización de los parámetros en el IoT device
    K_previous = CA_K_previous
    
    # Guardar los parámetros de registro
    registration_parameters = {
        "state": state,
        "C_1": C_1,
        "IoT_Identity": IoT_Identity,
        "K_previous": K_previous,
        "T_j": T_j
    }
    logger.info(f"Registro completado exitosamente con los siguientes parámetros: {registration_parameters}")

#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################
def mutualAuthentication():
    """
    Protocolo de autenticación mutua para el dispositivo IoT.
    Este proceso asegura la autenticidad y sincronización de claves entre el dispositivo IoT y el gateway.
    """
    
    global registration_parameters

    try:
         # Inicializar el socket persistente
        initialize_socket()
        
        # Paso 1: Enviar mensaje inicial ("hello") al gateway
        message = {"step": "hello", "message": "hello"}
        response = send_and_receive_persistent_socket(message)
        logger.info("Mensaje 'hello' enviado al Gateway.")
        
        # Paso 2: Recibir el token de autenticación del gateway
        if not all(key in response for key in ["G_r_1"]):
            raise KeyError("Faltan claves en la respuesta del Gateway.")
        G_r_1 = response["G_r_1"]
        logger.info(f"Token de autenticación recibido: G_r_1={G_r_1}.")

        # Paso 3: Calcular claves y parámetros cifrados al IoT gateway
        message, r_3, K_i = IoTobfuscationForR_2_ID(G_r_1)
        
        ## message = (A_M_1, ID_obfusacted, r_2_obfuscated, K_i_obfuscated, r_3_obfuscated)
        payload = {"step": "step3", "M_1": message[0], "ID*": message[1],
                   "r_2*": message[2], "K_i*": message[3], "r_3*": message[4]}
        response = send_and_receive_persistent_socket(payload)
        logger.info("Mensaje cifrado enviado al Gateway.")

        # Paso 4: Recibir claves y sincronización G_M_2, Sync_IoT_G del gateway 
        data = response.json()
        
        ## message = K_i_next_obfuscated
        if not all(key in response for key in ["K_i_next_obfuscated", "K_s", "state", "C_1"]):
            raise KeyError("Faltan claves en la respuesta del Gateway.")
        message, IoT_K_s, state, IoT_C_1 = computeNextSessionKey(
            response, G_r_1, r_3, K_i, registration_parameters["C_1"], registration_parameters["state"]
        )

        # Paso 5: Enviar claves obfuscadas para la siguiente sesión
        
        ## K_i_next_obfuscated
        payload = {"step": "step5", "K_i_next_obfuscated": message}
        response = send_and_receive_persistent_socket(payload)
        logger.info("Claves obfuscadas enviadas al Gateway.")
        
        # Paso 6: Recibir mensaje M_4 del gateway y actualizar parámetros
        if not all(key in response for key in ["IoT_K_previous", "IoT_C_1", "state"]):
            raise KeyError("Faltan claves en la respuesta del Gateway.")
        IoT_K_previous, IoT_C_1, state = updatingChallengeDPUFconfiguration(
            response, IoT_K_s, G_r_1, r_3, registration_parameters["K_previous"], K_i, IoT_C_1, state
        )

        # Paso 7: Actualizar los parámetros locales
        registration_parameters.update({
            "K_previous": IoT_K_previous,
            "state": state,
            "C_1": IoT_C_1,
        })
        logger.info("Parámetros del dispositivo IoT actualizados correctamente.")
    except KeyError as e:
        logger.error(f"Error de datos faltantes en la respuesta: {e}")
    except socket.error as e:
        logger.error(f"Error en la comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
    finally:
        close_socket() 

def IoTobfuscationForR_2_ID(G_r_1):
    r_2 = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    r_3 = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  

    IoT_Identity = registration_parameters["IoT_Identity"]
    C_1 = registration_parameters["C_1"]
    state = registration_parameters["state"]
    K_previous = registration_parameters["K_previous"]
    T_j = registration_parameters["T_j"]
    
    ID_obfusacted=IoT_Identity^Hash(G_r_1,r_2)
    K_i=DPUF(C_1,state)
    K_i_obfuscated=K_i^K_previous
    A_M_1=Hash(K_i,G_r_1,r_3)
    r_2_obfuscated=FPUF(C_F0)^r_2
    r_2_obfuscated=r_2_obfuscated^FPUF(C_F1)^T_j
    r_3_obfuscated=r_3^K_i

    return (A_M_1, ID_obfusacted, r_2_obfuscated, K_i_obfuscated, r_3_obfuscated), r_3, K_i

def computeNextSessionKey(data, G_r_1, r_3, K_i, C_1, state):
    #G_M_2, Sync_G
    G_M_2 = data[0]
    Sync_G = data[1]

    assert G_M_2==Hash(K_i,Sync_G,G_r_1,r_3), "The authentication of the Gateway on the IoT device has failed"
    if Sync_G==-1:
        C_1=Hash(C_1)
        state=Hash(state)
    K_i=DPUF(C_1,state)
    K_i_next=DPUF(Hash(C_1),Hash(state))
    K_i_next_obfuscated=K_i_next^K_i
    K_s=Hash(G_r_1,r_3,K_i)
    logger.info("The IoT session Key: {K_s}")
    return K_i_next_obfuscated, K_s, state, C_1

def updatingChallengeDPUFconfiguration(M_4,K_s,G_r_1,r_3,K_previous,K_i,C_1,state):
    assert M_4 == Hash(K_s,G_r_1,r_3), "The synchronization keys between the IoT device and the gateway have not been updated on the IoT device"
    C_1 = Hash(C_1)
    K_previous=K_i
    state=Hash(state)  
    return  K_previous,C_1,state

#######################################################
#                      AUXILIARES                     #
#######################################################
def initialize_socket():
    """
    Inicializa un socket persistente para comunicarse con el Gateway.
    """
    global gateway_socket
    logger.info(f"Conectado al Gateway en {GATEWAY_HOST}:{GATEWAY_PORT}")
    if gateway_socket is None:
        try:
            gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            gateway_socket.connect((GATEWAY_HOST, GATEWAY_PORT))
            logger.info(f"Conectado al Gateway en {GATEWAY_HOST}:{GATEWAY_PORT}")
        except socket.error as e:
            logger.error(f"Error al conectar con el Gateway: {e}")
            gateway_socket = None
            raise e
        
def close_socket():
    """
    Cierra el socket persistente.
    """
    global gateway_socket
    if gateway_socket:
        try:
            gateway_socket.close()
            logger.info("Socket con el Gateway cerrado correctamente.")
        except socket.error as e:
            logger.error(f"Error al cerrar el socket: {e}")
        finally:
            gateway_socket = None

def send_and_receive_persistent_socket(message):
    """
    Enviar un mensaje al Gateway utilizando un socket persistente y recibir la respuesta.
    """
    global gateway_socket
    try:
        if gateway_socket is None:
            initialize_socket()
        gateway_socket.sendall(json.dumps(message).encode('utf-8'))  # Enviar mensaje
        response = gateway_socket.recv(4096)                        # Recibir respuesta
        return json.loads(response.decode('utf-8'))                 # Retornar respuesta decodificada
    except socket.error as e:
        logger.error(f"Error en la comunicación por socket persistente: {e}")
        gateway_socket = None  # Marcar el socket como no válido
        raise e

def sendData():
    while True:
        sensor_data = {"DEV-temperature": random.uniform(20.0, 30.0), "DEV-humidity": random.uniform(50, 70)}
        try:
            response = requests.post(CA_URL, json=sensor_data)
            logger.info(f"[DEVICE] Data sent: {sensor_data}, Response: {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending data: {e}")
        time.sleep(25)
        
if __name__ == '__main__':
    #logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8012.")
    #start_http_server(8012, addr="0.0.0.0")
    registrationIoT()
    #mutualAuthentication()
    #sendData()