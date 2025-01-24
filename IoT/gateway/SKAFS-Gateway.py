import binascii
import requests
import logging
import random
import socket
import json
import base64
import os

from common.cripto_primitivas import *

from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/logs/SKAFS-gateway.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Gateway")

# API expuesto para el CA
CA_URL = "http://skafs-cloud:8001"

# Configuración del servidor socket
HOST = "0.0.0.0"  # Dirección IP del Gateway
PORT = 5000         # Puerto del Gateway
CA_HOST = "skafs-cloud"      # Dirección de la CA
CA_PORT = 5001             # Puerto de la CA
cloud_socket = None

# Identidad única de la CA
CA_Identity = None

# Parámetros de registro
registration_parameters = {}

#######################################################
#               SERVIDOR SOCKET GATEWAY               #
#######################################################
def startGatewayServer():
    """
    Inicia el servidor socket para manejar conexiones del IoT Device.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logger.info(f"Socket Gateway escuchando en {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            logger.info(f"Conexión aceptada de {addr}")
            handleMutualAuthentication(client_socket)

#######################################################
#                   REGISTRO GATEWAY                  #
#######################################################
            
def registrationGateway():
    global registration_parameters, CA_Identity
    
    # Paso 1: Generar y enviar ID del gateway
    Gateway_Identity = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000 
    logger.info(f"[REG] Gateway_Identity: {Gateway_Identity}")
    
    try:
        response = requests.post(
            f"{CA_URL}/registration/gateway",
            json={"Gateway_Identity": Gateway_Identity}
        )
        response.raise_for_status()
        logger.info("[REG] Enviado Gateway_Identity al CA.")
    except requests.RequestException as e:
        logger.error(f"[REG] Error al enviar Gateway_Identity al CA: {e}")
        return
    
    # Paso 2: Recibir CA_MK_G_CA, CA_Sync_K_G_CA_previous, CA_r_1_previous
    try:
        response_data = response.json()
        CA_Identity = response_data["CA_Identity"]
        CA_MK_G_CA = response_data["CA_MK_G_CA"]
        CA_Sync_K_G_CA_previous = response_data["CA_Sync_K_G_CA_previous"]
        CA_r_1_previous = response_data["CA_r_1_previous"]
        logger.info("[REG] Recibidos parámetros del CA para el Gateway.")
    except KeyError as e:
        logger.error(f"[REG] Parámetro faltante en la respuesta del CA: {e}")
        return
    except requests.RequestException as e:
        logger.error(f"[REG] Error al recibir datos del CA: {e}")
        return
    
    # Calcular claves derivadas en el Gateway
    G_MK_G_CA = CA_MK_G_CA
    G_Sync_K_G_CA_previous = CA_Sync_K_G_CA_previous
    G_r_1_previous = CA_r_1_previous
    G_Sync_K_G_CA = Hash(G_Sync_K_G_CA_previous, G_r_1_previous)
    logger.info(f"[REG] Claves calculadas en el Gateway: G_Sync_K_G_CA={G_Sync_K_G_CA}")
    
    # Paso 3: Guardar G_MK_G_CA
    registration_parameters = {
        "Gateway_Identity": Gateway_Identity,
        "G_MK_G_CA": G_MK_G_CA,
        "G_Sync_K_G_CA_previous": G_Sync_K_G_CA_previous,
        "G_r_1_previous": G_r_1_previous,
        "G_Sync_K_G_CA": G_Sync_K_G_CA,
        "Sync_IoT_G": 0
    }
    logger.info(f"[REG] Registro completado exitosamente con los siguientes parámetros: {registration_parameters}")

#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################

def handleMutualAuthentication(device_sock):
    
    """
    Maneja la conexión de un cliente (IoT Device) y ejecuta el protocolo de autenticación mutua.
    """
    global registration_parameters
    try:
        # Paso 1: Recibir mensaje "hello" del dispositivo IoT
        data = json.loads(device_sock.recv(4096).decode('utf-8'))
        if data.get("step") != "hello":
            raise ValueError("Paso incorrecto recibido del dispositivo.")
        IoT_HelloMsg = data.get("message", "No message")
        logger.info(f"[AUTH] Mensaje recibido del IoT Device: {IoT_HelloMsg}")

        # Paso 2: Generar r_1 y enviarlo al dispositivo IoT
        G_r_1 = int.from_bytes(os.urandom(1024),'big')% 90000 + 10000 
        payload = {"G_r_1": G_r_1}
        device_sock.sendall(json.dumps(payload).encode('utf-8'))
        logger.info(f"[AUTH] r_1 generado y enviado al dispositivo IoT: {G_r_1}")

        # Paso 3: Recibir M_1, ID*, r_2*, K_i*, r_3* del dispositivo IoT
        data = json.loads(device_sock.recv(4096).decode('utf-8'))
        if not all(key in data for key in ["M_1", "ID*", "r_2*", "K_i*", "r_3*"]):
            raise KeyError("[AUTH] Faltan claves en la respuesta del dispositivo IoT.")
        # Crear un nuevo diccionario excluyendo "step"
        IoT_M1 = {k: v for k, v in data.items() if k != "step"}
        logger.info(f"[AUTH] Datos recibidos del IoT Device: {IoT_M1}")
            
        # Paso 4: Generar parámetros de autenticación y enviarlos a la CA
        
        # Inicializar el socket persistente con la CA
        initialize_socket()
        G_nonce = int.from_bytes(os.urandom(1024),'big') % 90000 + 10000 
        logger.info(f"[AUTH] registration_parameters: {registration_parameters}")
        G_MK_G_CA = registration_parameters["G_MK_G_CA"]
        Gateway_Identity = registration_parameters["Gateway_Identity"]
        G_Sync_K_G_CA = registration_parameters["G_Sync_K_G_CA"]
        returnData = generateSigma1Sigma2Epison1(
            G_nonce, G_MK_G_CA, Gateway_Identity, G_Sync_K_G_CA, G_r_1, IoT_M1
        )
        iv = returnData[9]
        HashResult = returnData[10]
        message = returnData[:10]
        payload = {
            "Gateway_Identity": message[0],
            "G_nonce": message[1],
            "G_sigma_1": message[2],
            "G_sigma_2": message[3],
            "Epison_1_1": message[4],
            "Epison_1_2": message[5],
            "Epison_1_3": message[6],
            "Epison_1_4": message[7],
            "Epison_1_5": message[7],
            #"iv": iv.hex(),
            "iv": iv
        }
        ca_response = send_and_receive_persistent_socket(payload)
        logger.info("[AUTH] Parámetros enviados a la CA para autenticación mutua.")

        # Paso 5: Recibir respuesta de la CA
        if not all(key in ca_response for key in ["CA_sigma_3", "Epison_2_1", "Epison_2_2", "Epison_2_3", "Epison_2_4", "D_sync_CA_G"]):
            raise KeyError("[AUTH] Faltan claves en la respuesta de la CA.")
        CA_sigma_3 = ca_response["CA_sigma_3"]
        Epison_2_1 = ca_response["Epison_2_1"]
        Epison_2_2 = ca_response["Epison_2_2"]
        Epison_2_3 = ca_response["Epison_2_3"]
        Epison_2_4 = ca_response["Epison_2_4"]
        D_sync_CA_G = ca_response["D_sync_CA_G"]
        logger.info("[AUTH] Claves y parámetros de sincronización recibidos de la CA.")

        # Paso 6: Enviar G_M_2 y Sync_IoT_G al dispositivo IoT
        returnData = checkingSynchronizationBetGatewayIoT(
            [CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G],
            G_nonce,
            IoT_M1,
            G_r_1,
            iv,
            HashResult,
        )
        # message=G_M_2, Sync_IoT_G,
        message = returnData[:2]        
        G_K_a = returnData[2]
        G_K_previous = returnData[3]
        G_K_current = returnData[4]
        G_r_3 = returnData[5]
        
        payload = {"G_M_2": message}
        device_sock.sendall(json.dumps(payload).encode('utf-8'))
        logger.info("[AUTH] Claves de sincronización enviadas al dispositivo IoT.")

        # Paso 7: Recibir data=IoT_K_i_next_obfuscated del IoT
        data = json.loads(device_sock.recv(4096).decode('utf-8'))
        if "K_i_next_obfuscated" not in data:
            raise KeyError("[AUTH] Falta K_i_next_obfuscated en la respuesta del dispositivo IoT.")
        
        returnData = gettingEncryptingNextSessionKey(data["K_i_next_obfuscated"], iv, HashResult, G_K_a)
        Epison_3_1 = returnData[0]
        G_IoT_K_i_next = returnData[1]
        logger.info("[AUTH] Recibido IoT_K_i_next_obfuscated del dispositivo IoT.")

        # Paso 8: Enviar Epison_3_1 a la CA
        payload = {"Epison_3_1": Epison_3_1}
        ca_response = send_and_receive_persistent_socket(payload)
        logger.info(f"[AUTH] Epison_3_1={Epison_3_1} enviado a la CA.")

        # Paso 9: Recibir M_3 de la CA
        if "M_3" not in ca_response:
            raise KeyError("Falta M_3 en la respuesta de la CA.")
        CA_M3 = ca_response["M_3"]
        logger.info("[AUTH] Recibido M_3 de la CA.")

        # Paso 10: Enviar M_4 al dispositivo IoT
        message = updatingSynchronizationKeys(
            CA_M3, G_r_1, G_r_3, G_K_previous, G_K_current, G_IoT_K_i_next, G_Sync_K_G_CA
        )
        device_sock.sendall(json.dumps({"M_4": message}).encode('utf-8'))
        logger.info("[AUTH] Mensaje M_4 enviado al dispositivo IoT.")  
        logger.info("[AUTH] Autenticación mutua culminada.")
    except KeyError as e:
        logger.error(f"Error de clave faltante en los datos recibidos: {e}")
    except Exception as e:
        logger.error(f"Error inesperado durante la autenticación mutua: {e}")
    finally:
        device_sock.close()
        close_socket() 

def generateSigma1Sigma2Epison1(G_nonce,G_MK_G_CA,Gateway_Identity,G_Sync_K_G_CA, G_r_1, IoT_M1):
    G_sigma_1=Hash(G_MK_G_CA,Gateway_Identity,G_nonce)
    G_sigma_2=Hash(G_Sync_K_G_CA,Gateway_Identity,G_nonce)

    iv = Random.new().read(AES.block_size)
    h = hashlib.new('sha256')
    h.update(G_Sync_K_G_CA.to_bytes(32, 'big'))
    HashResult=bytes(h.hexdigest(),'utf-8')
    
    IoT_ID_obfusacted=IoT_M1["ID*"]
    IoT_r_2_obfuscated=IoT_M1["r_2*"]
    IoT_r_3_obfuscated=IoT_M1["r_3*"]
    IoT_K_i_obfuscated=IoT_M1["K_i*"]
        
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_1=ENC.encrypt(IoT_ID_obfusacted.to_bytes(32,'big'))
    
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_2=ENC.encrypt(IoT_r_2_obfuscated.to_bytes(32,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_3=ENC.encrypt(IoT_r_3_obfuscated.to_bytes(32,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_4=ENC.encrypt(G_r_1.to_bytes(32,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_5=ENC.encrypt(IoT_K_i_obfuscated.to_bytes(32,'big'))

    return Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5, iv, HashResult
    
def checkingSynchronizationBetGatewayIoT(data, G_nonce, IoT_M_1, G_r_1, iv,HashResult):
    CA_sigma_3 = data[0]
    Epison_2_1 = data[1]
    Epison_2_2 = data[2]
    Epison_2_3 = data[3]
    Epison_2_4 = data[4]
    D_sync_CA_G= data[5]

    IoT_K_i_obfuscated = IoT_M_1["K_i*"]
    IoT_A_M_1 = IoT_M_1["M_1"]
    IoT_r_3_obfuscated = IoT_M_1["r_3*"]

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_before_previous=int.from_bytes(DEC.decrypt(Epison_2_1),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_previous=int.from_bytes(DEC.decrypt(Epison_2_2),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_current = int.from_bytes(DEC.decrypt(Epison_2_3),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_r_1_previous=int.from_bytes(DEC.decrypt(Epison_2_4),'big')
    
    if D_sync_CA_G==-1:
        registration_parameters["G_Sync_K_G_CA"]=Hash(G_Sync_K_G_CA_previous,G_r_1_previous)
    
    G_Sync_K_G_CA_previous = registration_parameters["G_Sync_K_G_CA_previous"]
    G_MK_G_CA = registration_parameters["G_MK_G_CA"]
    assert CA_sigma_3==Hash(G_MK_G_CA,CA_Identity,D_sync_CA_G,G_nonce+1), "The authentication of the CA on the gateway side has failed"

    if IoT_K_i_obfuscated^G_K_previous==G_K_current:
        Sync_IoT_G = 0
        G_K_a = G_K_current
        G_r_3 = IoT_r_3_obfuscated^G_K_current
        assert IoT_A_M_1==Hash(G_K_current,G_r_1,G_r_3), "The K_c has not been used in the first authentication message"
    elif IoT_K_i_obfuscated^G_K_before_previous==G_K_previous:
        Sync_IoT_G = -1
        G_K_a = G_K_previous
        G_r_3 = IoT_r_3_obfuscated^G_K_previous
        assert (IoT_A_M_1==Hash(G_K_previous,G_r_1,G_r_3)), "The K_p has not been used in the generation of the authentication message"
    else:
        logger.error("No coinciden las llaves de sinocrnización")
        
    G_M_2 = Hash(G_K_a,Sync_IoT_G,G_r_1,G_r_3)
    registration_parameters["Sync_IoT_G"] = Sync_IoT_G

    return G_M_2, Sync_IoT_G, G_K_a, G_K_previous, G_K_current, G_r_3

def gettingEncryptingNextSessionKey(IoT_K_i_next_obfuscated, iv, HashResult, G_K_a):    
    G_IoT_K_i_next = IoT_K_i_next_obfuscated^G_K_a
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_3_1 = ENC.encrypt(G_IoT_K_i_next.to_bytes(32,'big'))

    return Epison_3_1, G_IoT_K_i_next

def updatingSynchronizationKeys(CA_M3, G_r_1, IoT_r_3, G_K_previous,G_K_current,G_IoT_K_i_next,G_Sync_K_G_CA):

    G_K_s = Hash(G_r_1,IoT_r_3,G_K_current)
    logger.info(f"[AUTH] La llave de sesión en el Gateway es: {G_K_s}")

    ####### Update the synchronization keys ###############################
    G_K_before_previous = G_K_previous
    G_K_previous = G_K_current
    G_K_current  =G_IoT_K_i_next
    registration_parameters["G_r_1_previous"]=G_r_1

    ##### Update the gateway & CA synchronization keys ###########
    registration_parameters["G_Sync_K_G_CA_previous"]=G_Sync_K_G_CA
    G_Sync_K_G_CA = Hash(G_Sync_K_G_CA,G_r_1)

    assert CA_M3==Hash(G_K_before_previous,G_K_previous,G_K_current,G_Sync_K_G_CA), "[AUTH] Las llaves de sincronización entre el CA y el Gateway no se han actualizado en este último."
    M_4 = Hash(G_K_s,G_r_1,IoT_r_3)

    return M_4

#######################################################
#                      AUXILIARES                     #
#######################################################

def initialize_socket():
    """
    Inicializa un socket persistente para comunicarse con el CA.
    """
    global cloud_socket
    if cloud_socket is None:
        try:
            cloud_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cloud_socket.connect((CA_HOST, CA_PORT))
            logger.info(f"Conectado al CA en {CA_HOST}:{CA_PORT}")
        except socket.error as e:
            logger.error(f"Error al conectar con el CA: {e}")
            cloud_socket = None
            raise e
        
def close_socket():
    """
    Cierra el socket persistente.
    """
    global cloud_socket
    if cloud_socket:
        try:
            cloud_socket.close()
            logger.info("Socket con el CA cerrado correctamente.")
        except socket.error as e:
            logger.error(f"Error al cerrar el socket: {e}")
        finally:
            cloud_socket = None

def send_and_receive_persistent_socket(message_dict):
    """
    Enviar un mensaje al CA utilizando un socket persistente y recibir la respuesta.
    """
    global cloud_socket
    try:
        if cloud_socket is None:
            initialize_socket()
        encoded_message = {}
        for key in message_dict:
            value = message_dict[key]
            if isinstance(value, bytes):
                encoded_message[key] = base64.b64encode(value).decode('utf-8')  # Convertir bytes a base64 y luego a str
            else:
                encoded_message[key] = value
        #logger.info(f"send_and_receive_persistent_socket- encoded_message={encoded_message}")
        cloud_socket.sendall(json.dumps(encoded_message).encode('utf-8'))  # Enviar mensaje
        
        response = cloud_socket.recv(4096)                        # Recibir respuesta
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
        cloud_socket = None  # Marcar el socket como no válido
        raise e

def sendData():
    while True:
        sensor_data = {"GTW-temperature": random.uniform(20.0, 30.0), "GTW-humidity": random.uniform(50, 70)}
        try:
            response = requests.post(CA_URL, json=sensor_data)
            logger.info(f"[GATEWAY] Data sent: {sensor_data}, Response: {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending data: {e}")
        time.sleep(25)
        
if __name__ == '__main__':
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8010.")
    start_http_server(8010)
    registrationGateway()
    startGatewayServer()
    #sendData()
    
    