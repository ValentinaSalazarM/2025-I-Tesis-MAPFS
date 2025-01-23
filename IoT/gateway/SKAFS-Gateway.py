import requests
import logging
import random
import socket
import json
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
    logger.info(f"Gateway_Identity: {Gateway_Identity}")
    
    try:
        response = requests.post(
            f"{CA_URL}/registration/gateway",
            json={"Gateway_Identity": Gateway_Identity}
        )
        response.raise_for_status()
        logger.info("Enviado Gateway_Identity al CA.")
    except requests.RequestException as e:
        logger.error(f"Error al enviar Gateway_Identity al CA: {e}")
        return
    
    # Paso 2: Recibir CA_MK_G_CA, CA_Sync_K_G_CA_previous, CA_r_1_previous
    try:
        response_data = response.json()
        CA_Identity = response_data["CA_Identity"]
        CA_MK_G_CA = response_data["CA_MK_G_CA"]
        CA_Sync_K_G_CA_previous = response_data["CA_Sync_K_G_CA_previous"]
        CA_r_1_previous = response_data["CA_r_1_previous"]
        logger.info("Recibidos parámetros del CA para el Gateway.")
    except KeyError as e:
        logger.error(f"Parámetro faltante en la respuesta del CA: {e}")
        return
    except requests.RequestException as e:
        logger.error(f"Error al recibir datos del CA: {e}")
        return
    
    # Calcular claves derivadas en el Gateway
    G_MK_G_CA = CA_MK_G_CA
    G_Sync_K_G_CA_previous = CA_Sync_K_G_CA_previous
    G_r_1_previous = CA_r_1_previous
    G_Sync_K_G_CA = Hash(G_Sync_K_G_CA_previous, G_r_1_previous)
    logger.info(f"Claves calculadas en el Gateway: G_Sync_K_G_CA={G_Sync_K_G_CA}")
    
    # Paso 3: Guardar G_MK_G_CA
    registration_parameters = {
        "Gateway_Identity": Gateway_Identity,
        "G_MK_G_CA": G_MK_G_CA,
        "G_Sync_K_G_CA_previous": G_Sync_K_G_CA_previous,
        "G_r_1_previous": G_r_1_previous,
        "G_Sync_K_G_CA": G_Sync_K_G_CA,
        "Sync_IoT_G": 0
    }
    logger.info(f"Registro del Gateway completado con los parámetros: {registration_parameters}")

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
        logger.info(f"PASO 1: {data}")    
        if data.get("step") != "hello":
            raise ValueError("Paso incorrecto recibido del dispositivo.")
        IoT_HelloMsg = data.get("message", "No message")
        logger.info(f"Mensaje recibido del IoT Device: {IoT_HelloMsg}")

        # Paso 2: Generar r_1 y enviarlo al dispositivo IoT
        G_r_1 = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
        payload = {"G_r_1": G_r_1}
        device_sock.sendall(json.dumps(payload).encode('utf-8'))
        logger.info(f"PASO 2: r_1 generado y enviado al dispositivo IoT: {G_r_1}")

        # Paso 3: Recibir M_1, ID*, r_2*, K_i*, r_3* del dispositivo IoT
        data = json.loads(device_sock.recv(4096).decode('utf-8'))
        if not all(key in data for key in ["M_1", "ID*", "r_2*", "K_i*", "r_3*"]):
            raise KeyError("Faltan claves en la respuesta del dispositivo IoT.")
        # Crear un nuevo diccionario excluyendo "step"
        payload_reduced = {k: v for k, v in data.items() if k != "step"}
        logger.info(f"PASO 3: Datos recibidos del IoT Device: {payload_reduced}")
            
        # Paso 4: Generar parámetros de autenticación y enviarlos a la CA
        G_nonce = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
        logger.info(f"PASO 4: registration_parameters: {registration_parameters}")
        G_MK_G_CA = registration_parameters["G_MK_G_CA"]
        Gateway_Identity = registration_parameters["Gateway_Identity"]
        G_Sync_K_G_CA = registration_parameters["G_Sync_K_G_CA"]
        logger.info(f"PASO 4: generateSigma1Sigma2Epison1: {G_nonce}, {G_MK_G_CA}, {Gateway_Identity}, {G_Sync_K_G_CA}, {G_r_1}, {payload_reduced}")
        returnData = generateSigma1Sigma2Epison1(
            G_nonce, G_MK_G_CA, Gateway_Identity, G_Sync_K_G_CA, G_r_1, payload_reduced
        )
        logger.info(f"PASO 4: returnData: {returnData}")
        iv = returnData[9]
        HashResult = returnData[10]
        message = returnData[:10]
        payload = {
            "G_nonce": G_nonce,
            "G_sigma_1": message[0],
            "G_sigma_2": message[1],
            "Epison_1_1": message[2],
            "Epison_1_2": message[3],
            "Epison_1_3": message[4],
            "Epison_1_4": message[5],
            "Epison_1_5": message[6],
            "iv": iv.hex(),
        }
        ca_response = sendReceiveData(CA_HOST, CA_PORT, payload)
        logger.info("Parámetros enviados a la CA para autenticación mutua.")

        # Paso 5: Recibir respuesta de la CA
        if not all(key in ca_response for key in ["CA_sigma_3", "Epison_2_1", "Epison_2_2", "Epison_2_3", "Epison_2_4", "D_sync_CA_G"]):
            raise KeyError("Faltan claves en la respuesta de la CA.")
        CA_sigma_3 = ca_response["CA_sigma_3"]
        Epison_2_1 = ca_response["Epison_2_1"]
        Epison_2_2 = ca_response["Epison_2_2"]
        Epison_2_3 = ca_response["Epison_2_3"]
        Epison_2_4 = ca_response["Epison_2_4"]
        D_sync_CA_G = ca_response["D_sync_CA_G"]
        logger.info("Claves y parámetros de sincronización recibidos de la CA.")

        # Paso 6: Enviar G_M_2 y Sync_IoT_G al dispositivo IoT
        returnData = checkingSynchronizationBetGatewayIoT(
            [CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4],
            G_nonce,
            message,
            G_r_1,
            iv,
            HashResult,
        )
        # G_M_2, Sync_IoT_G,
        message = returnData[:2]
        G_K_a = returnData[2]
        G_K_previous = returnData[3]
        G_K_current = returnData[4]
        G_r_3 = returnData[5]
        
        payload = {"G_M_2": message}
        device_sock.sendall(json.dumps(payload).encode('utf-8'))
        logger.info("Claves de sincronización enviadas al dispositivo IoT.")

        # Paso 7: Recibir data=IoT_K_i_next_obfuscated del IoT
        data = json.loads(device_sock.recv(4096).decode('utf-8'))
        if "IoT_K_i_next_obfuscated" not in data:
            raise KeyError("Falta IoT_K_i_next_obfuscated en la respuesta del dispositivo IoT.")
        
        ## Epison_3_1, G_IoT_K_i_next
        returnData = gettingEncryptingNextSessionKey(data, iv, HashResult, G_K_a)
        Epison_3_1 = returnData[0]
        G_IoT_K_i_next = returnData[1]
        logger.info("Recibido IoT_K_i_next_obfuscated del dispositivo IoT.")

        # Paso 8: Enviar Epison_3_1 a la CA
        payload = {"Epison_3_1": Epison_3_1}
        ca_response = sendReceiveData(CA_HOST, CA_PORT, payload)
        logger.info("Epison_3_1 enviado a la CA.")

        # Paso 9: Recibir M_3 de la CA
        if "M_3" not in ca_response:
            raise KeyError("Falta M_3 en la respuesta de la CA.")
        CA_M3 = ca_response["M_3"]
        logger.info("Recibido M_3 de la CA.")

        # Paso 10: Enviar M_4 al dispositivo IoT
        message = updatingSynchronizationKeys(
            CA_M3, G_r_1, G_r_3, G_K_previous, G_K_current, G_IoT_K_i_next, G_Sync_K_G_CA
        )
        device_sock.sendall(json.dumps({"M_4": message}).encode('utf-8'))
        logger.info("Mensaje M_4 enviado al dispositivo IoT.")  
        
    except KeyError as e:
        logger.error(f"Error de clave faltante en los datos recibidos: {e}")
    except Exception as e:
        logger.error(f"Error inesperado durante la autenticación mutua: {e}")
    finally:
        device_sock.close()

def generateSigma1Sigma2Epison1(G_nonce,G_MK_G_CA,Gateway_Identity,G_Sync_K_G_CA, G_r_1, IoT_M1):
    G_sigma_1=Hash(G_MK_G_CA,Gateway_Identity,G_nonce)
    G_sigma_2=Hash(G_Sync_K_G_CA,Gateway_Identity,G_nonce)

    iv = Random.new().read(AES.block_size)
    h = hashlib.new('sha256')
    h.update(G_Sync_K_G_CA.to_bytes(32, 'big'))
    HashResult=bytes(h.hexdigest(),'utf-8')

    logger.info(f"generateSigma1Sigma2Epison1 IoT_M1:{IoT_M1}")  
    
    IoT_ID_obfusacted=IoT_M1[1]
    IoT_r_2_obfuscated=IoT_M1[2]
    IoT_r_3_obfuscated=IoT_M1[4]
    IoT_K_i_obfuscated=IoT_M1[3]
    
    logger.info(f"generateSigma1Sigma2Epison1 IoT_ID_obfusacted:{IoT_ID_obfusacted}, IoT_r_2_obfuscated:{IoT_r_2_obfuscated}, IoT_r_3_obfuscated:{IoT_r_3_obfuscated}, IoT_K_i_obfuscated:{IoT_K_i_obfuscated}")
    
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_1=ENC.encrypt(IoT_ID_obfusacted.to_bytes(32,'big'))
    logger.info(f"Epison_1_1: {Epison_1_1}")
    
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_2=ENC.encrypt(IoT_r_2_obfuscated.to_bytes(32,'big'))
    logger.info(f"Epison_1_2: {Epison_1_2}")

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_3=ENC.encrypt(IoT_r_3_obfuscated.to_bytes(32,'big'))
    logger.info(f"Epison_1_3: {Epison_1_3}")

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_4=ENC.encrypt(G_r_1.to_bytes(32,'big'))
    logger.info(f"Epison_1_4: {Epison_1_4}")

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_5=ENC.encrypt(IoT_K_i_obfuscated.to_bytes(32,'big'))
    logger.info(f"Epison_1_5: {Epison_1_5}")

    return Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5, iv, HashResult
    
def checkingSynchronizationBetGatewayIoT(data, G_nonce, IoT_M_1, G_r_1, iv,HashResult):
    #CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G
    CA_sigma_3= data[0]
    Epison_2_1= data[1]
    Epison_2_2= data[2]
    Epison_2_3= data[3]
    Epison_2_4= data[4]
    D_sync_CA_G= data[5]
    IoT_K_i_obfuscated= IoT_M_1[3]
    IoT_A_M_1= IoT_M_1[0]
    IoT_r_3_obfuscated= IoT_M_1[4]

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_before_previous=int.from_bytes(DEC.decrypt(Epison_2_1),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_previous=int.from_bytes(DEC.decrypt(Epison_2_2),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_current=int.from_bytes(DEC.decrypt(Epison_2_3),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_r_1_previous=int.from_bytes(DEC.decrypt(Epison_2_4),'big')

    G_Sync_K_G_CA_previous = registration_parameters["G_Sync_K_G_CA_previous"]
    G_MK_G_CA = registration_parameters["G_MK_G_CA"]
    
    if D_sync_CA_G==-1:
        G_Sync_K_G_CA=Hash(G_Sync_K_G_CA_previous,G_r_1_previous)
    
    assert CA_sigma_3==Hash(G_MK_G_CA,CA_Identity,D_sync_CA_G,G_nonce+1), "The authentication of the CA on the gateway side has failed"
    
    if IoT_K_i_obfuscated^G_K_previous==G_K_current:
        Sync_IoT_G=0
        G_K_a = G_K_current
        G_r_3=IoT_r_3_obfuscated^G_K_current
        assert IoT_A_M_1==Hash(G_K_current,G_r_1,G_r_3), "The K_c has not been used in the first authentication message"
    elif IoT_K_i_obfuscated^G_K_before_previous==G_K_previous:
        Sync_IoT_G=-1
        G_K_a = G_K_previous
        G_r_3=IoT_r_3_obfuscated^G_K_previous
        assert (IoT_A_M_1==Hash(G_K_previous,G_r_1,G_r_3)), "The K_p has not been used in the generation of the authentication message"
    else:
        logger.error("PASO 6: No coinciden.")
        
    G_M_2=Hash(G_K_a,Sync_IoT_G,G_r_1,G_r_3)
    registration_parameters["Sync_IoT_G"] = Sync_IoT_G

    return G_M_2, Sync_IoT_G, G_K_a, G_K_previous, G_K_current, G_r_3

def gettingEncryptingNextSessionKey(IoT_K_i_next_obfuscated, iv, HashResult, G_K_a):
    # IoT_K_i_next_obfuscated
    G_IoT_K_i_next=IoT_K_i_next_obfuscated^G_K_a
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_3_1=ENC.encrypt(G_IoT_K_i_next.to_bytes(32,'big'))

    return Epison_3_1, G_IoT_K_i_next

def updatingSynchronizationKeys(CA_M3, G_r_1, IoT_r_3, G_K_previous,G_K_current,G_IoT_K_i_next,G_Sync_K_G_CA):

    G_K_s=Hash(G_r_1,IoT_r_3,G_K_current)
    logger.info("PASO 10: La llave de sesión en el gateway es {G_K_s}.")

    ####### Update the synchronization keys ###############################
    G_K_before_previous=G_K_previous
    G_K_previous=G_K_current
    G_K_current=G_IoT_K_i_next
    G_r_1_previous=G_r_1

    ##### Update the gateway & CA synchronization keys ###########
    G_Sync_K_G_CA_previous=G_Sync_K_G_CA
    G_Sync_K_G_CA=Hash(G_Sync_K_G_CA,G_r_1)

    assert CA_M3==Hash(G_K_before_previous,G_K_previous,G_K_current,G_Sync_K_G_CA), "The synchronization keys of the gateway and the CA have not been updated on the Gateway"
    M_4=Hash(G_K_s,G_r_1,IoT_r_3)

    return M_4

#######################################################
#                      AUXILIARES                     #
#######################################################

def sendReceiveData(host, port, message):
    """
    Enviar un mensaje mediante socket y recibir la respuesta.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(json.dumps(message).encode('utf-8'))  # Enviar mensaje
        response = sock.recv(4096)                         # Recibir respuesta
        return json.loads(response.decode('utf-8'))        # Decodificar y retornar respuesta
    
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
    #logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8010.")
    #start_http_server(8010, addr="0.0.0.0")
    registrationGateway()
    #startGatewayServer()
    #sendData()
    
    