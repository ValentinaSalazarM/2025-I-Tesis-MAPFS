import base64
import binascii
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

# Configuración del socket
GATEWAY_HOST = 'skafs-gateway'  # Dirección IP del Gateway
GATEWAY_PORT = 5000         # Puerto del Gateway

CA_HOST = "skafs-cloud"      # Dirección de la CA
CA_PORT = 5001             # Puerto de la CA

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
    """
    Registro del dispositivo IoT utilizando comunicación por sockets.
    """
    global registration_parameters, C_F0, C_F1

    try:
        # Configuración del socket para comunicarse con el CA
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((CA_HOST, CA_PORT))
            logger.info(f"[REG] Conectado al CA en {CA_HOST}:{CA_PORT}")

            # Generación de DPUF challenge y estado
            C_1 = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000
            state = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000

            # Generación de la identidad del IoT
            IoT_Identity = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000
            logger.info(f"[REG] IoT_Identity generado: {IoT_Identity}")

            # Paso 1: Solicitar desafíos al CA
            initial_request = {"operation": "register_device"}
            sock.sendall(json.dumps(initial_request).encode('utf-8'))
            logger.info("[REG] Enviada solicitud de registro al CA.")

            # Recibir desafíos C_F0 y C_F1
            data = sock.recv(4096)
            if not data:
                logger.error("[REG] No se recibieron desafíos del CA.")
                return
            challenges = json.loads(data.decode('utf-8'))
            C_F0 = challenges.get("C_F0")
            C_F1 = challenges.get("C_F1")
            if C_F0 is None or C_F1 is None:
                raise KeyError("Faltan desafíos C_F0 o C_F1 en la respuesta del CA.")
            logger.info("[REG] Desafíos recibidos del CA.")

            # Cálculo de las funciones FPUF y DPUF
            FPUF_Fixed_F0 = FPUF(C_F0)
            FPUF_Fixed_F1 = FPUF(C_F1)
            DPUF_C1 = DPUF(C_1, state)

            # Paso 2: Enviar datos calculados al CA
            payload = {
                "operation": "register_device",
                "IoT_Identity": IoT_Identity,
                "DPUF_C1": DPUF_C1,
                "FPUF_Fixed_F0": FPUF_Fixed_F0,
                "FPUF_Fixed_F1": FPUF_Fixed_F1,
            }
            sock.sendall(json.dumps(payload).encode('utf-8'))
            logger.info("[REG] Datos enviados al CA.")

            # Paso 3: Recibir respuesta del CA
            data = sock.recv(4096)
            if not data:
                logger.error("[REG] No se recibió respuesta del CA.")
                return
            response = json.loads(data.decode('utf-8'))
            CA_K_previous = response.get("CA_K_previous")
            T_j = response.get("IoT_T_j")
            if CA_K_previous is None or T_j is None:
                raise KeyError("Faltan datos en la respuesta del CA.")
            logger.info("[REG] Respuesta recibida del CA.")

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
            logger.info(f"[REG] Registro completado exitosamente con los siguientes parámetros: {registration_parameters}")

    except KeyError as e:
        logger.error(f"[REG] Clave faltante: {e}")
    except socket.error as e:
        logger.error(f"[REG] Error en la comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"[REG] Error inesperado durante el registro: {e}")

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
        logger.info("[AUTH] Mensaje 'hello' enviado al Gateway.")
        
        # Paso 2: Recibir el token de autenticación del gateway
        if not all(key in response for key in ["G_r_1"]):
            raise KeyError("Faltan claves en la respuesta del Gateway.")
        G_r_1 = response["G_r_1"]
        logger.info(f"[AUTH] Token de autenticación recibido: G_r_1={G_r_1}.")

        # Paso 3: Calcular claves y parámetros cifrados al IoT gateway
        message, r_3, K_i = IoTobfuscationForR_2_ID(G_r_1)
        
        logger.info(f"message={message}.")
        ## message = (A_M_1, ID_obfusacted, r_2_obfuscated, K_i_obfuscated, r_3_obfuscated)
        payload = {"step": "step3", "M_1": message[0], "ID*": message[1],
                   "r_2*": message[2], "K_i*": message[3], "r_3*": message[4]}
        response = send_and_receive_persistent_socket(payload)
        logger.info("[AUTH] Mensaje cifrado enviado al Gateway.")

        # Paso 4: Recibir claves y sincronización G_M_2, Sync_IoT_G del gateway         
        message, IoT_K_s, state, IoT_C_1 = computeNextSessionKey(
            response["G_M_2"], G_r_1, r_3, K_i, registration_parameters["C_1"], registration_parameters["state"]
        )

        # Paso 5: Enviar claves obfuscadas para la siguiente sesión
        payload = {"step": "step5", "K_i_next_obfuscated": message}
        response = send_and_receive_persistent_socket(payload)
        logger.info("[AUTH] Claves obfuscadas enviadas al Gateway.")
        
        # Paso 6: Recibir mensaje M_4 del gateway y actualizar parámetros
        if not all(key in response for key in ["M_4"]):
            raise KeyError("[AUTH] Faltan claves en la respuesta del Gateway.")
        IoT_K_previous, IoT_C_1, state = updatingChallengeDPUFconfiguration(
            response["M_4"], IoT_K_s, G_r_1, r_3, registration_parameters["K_previous"], K_i, IoT_C_1, state
        )

        # Paso 7: Actualizar los parámetros locales
        registration_parameters.update({
            "K_previous": IoT_K_previous,
            "state": state,
            "C_1": IoT_C_1,
        })
        logger.info("[AUTH] Parámetros del dispositivo IoT actualizados correctamente.")
        logger.info("[AUTH] Autenticación mutua culminada.")
    except KeyError as e:
        logger.error(f"[AUTH] Error de datos faltantes en la respuesta: {e}")
    except socket.error as e:
        logger.error(f"[AUTH] Error en la comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"[AUTH] Error inesperado: {e}")
    finally:
        close_socket() 

def IoTobfuscationForR_2_ID(G_r_1):
    r_2 = int.from_bytes(os.urandom(1024), 'big')  % 90000 + 10000  
    r_3 = int.from_bytes(os.urandom(1024), 'big')  % 90000 + 10000  

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
    assert G_M_2==Hash(K_i,Sync_G,G_r_1,r_3), "[AUTH] La autenticación del Gateway en el dispositivo IoT falló."
    if Sync_G==-1:
        C_1=Hash(C_1)
        state=Hash(state)
    K_i=DPUF(C_1,state)
    K_i_next=DPUF(Hash(C_1),Hash(state))
    K_i_next_obfuscated=K_i_next^K_i
    K_s=Hash(G_r_1,r_3,K_i)
    logger.info(f"[AUTH] La llave de sesión en el dispositivo IoT es: {K_s}")
    return K_i_next_obfuscated, K_s, state, C_1

def updatingChallengeDPUFconfiguration(M_4,K_s,G_r_1,r_3,K_previous,K_i,C_1,state):
    assert M_4 == Hash(K_s,G_r_1,r_3), "[AUTH] Las llaves de sincronización entre el Gateway y el dispositivo IoT no se han actualizado en este último."
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

def send_and_receive_persistent_socket(message_dict):
    """
    Enviar un mensaje al Gateway utilizando un socket persistente y recibir la respuesta.
    """
    global gateway_socket
    try:
        if gateway_socket is None:
            initialize_socket()
        encoded_message = {}
        for key in message_dict:
            value = message_dict[key]
            if isinstance(value, bytes):
                encoded_message[key] = base64.b64encode(value).decode('utf-8')  # Convertir bytes a base64 y luego a str
            else:
                encoded_message[key] = value
        #logger.info(f"send_and_receive_persistent_socket- encoded_message={encoded_message}")
        gateway_socket.sendall(json.dumps(encoded_message).encode('utf-8'))  # Enviar mensaje
        
        response = gateway_socket.recv(4096)                        # Recibir respuesta
        received_message_dict = json.loads(response.decode('utf-8')) 
        decoded_message = {}
        for key, value in received_message_dict.items():
            if isinstance(value, str):  # Solo intentar decodificar cadenas
                try:
                    # Decodificar solo si es válido Base64
                    decoded_message[key] = base64.b64decode(value)
                except (ValueError, binascii.Error):
                    # Si no es Base64, mantener el valor original
                    decoded_message[key] = value
            else:
                # No es cadena, mantener el valor original
                decoded_message[key] = value
        #logger.info(f"send_and_receive_persistent_socket- decoded_response={decoded_message}")
        return decoded_message        
    except socket.error as e:
        logger.error(f"Error en la comunicación por socket persistente: {e}")
        gateway_socket = None  # Marcar el socket como no válido
        raise e
        
if __name__ == '__main__':
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8012.")
    start_http_server(8012)
    registrationIoT()
    mutualAuthentication()
