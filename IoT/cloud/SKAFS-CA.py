import requests
import logging
import uvicorn
import random
import socket
import json
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from common.cripto_primitivas import *

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/logs/SKAFS-cloud.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Cloud")

# Creación de la aplicación FastAPI
app = FastAPI()

# Configuración del servidor socket para que acepte conexiones desde otros contenedores
HOST = "0.0.0.0"  
PORT = 5001         

# Generación de la identidad y la clave a largo plazo 
CA_Identity = K = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000    
K = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  

# Generación de desafíos fija (C_F0, C_F1) simulando PUF
C_F0 = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
C_F1 = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  

# Lista global para almacenar los sensores registrados
registered_devices = []
device_keys = {}  # Diccionario para almacenar variables por IoT_Identity
IoT_Identity = None

# Lista global para almacenar los gateways registrados
registered_gateways = []
gateway_keys = {}  # Diccionario para almacenar variables por Gateway_Identity
Gateway_Identity = None

#######################################################
#               SERVIDOR SOCKET CLOUD                 #
#######################################################

def startCloudServer():
    """
    Inicia el servidor socket para manejar conexiones del Gateway.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logger.info(f"Socket Cloud escuchando en {HOST}:{PORT}")

        while True:
            gateway_socket, addr = server_socket.accept()
            logger.info(f"Conexión aceptada de {addr}")

#######################################################
#              REGISTRO DISPOSITIVO IOT               #
#######################################################

# Modelos de datos para FastAPI
class IoTRegistrationRequest(BaseModel):
    IoT_Identity: int
    DPUF_C1: int
    FPUF_Fixed_F0: int
    FPUF_Fixed_F1: int

class IoTRegistrationResponse(BaseModel):
    CA_K_previous: int
    IoT_T_j: int

@app.get("/registration/challenges")
async def sendChallenges():
    """
    Endpoint para enviar los desafíos C_F0 y C_F1 al dispositivo IoT.
    """
    logger.info("Enviando desafíos C_F0 y C_F1 al IoT.")
    return {"C_F0": C_F0, "C_F1": C_F1}

@app.post("/registration/device")
async def registerDevice(data: IoTRegistrationRequest):
    """
    Recibir información del dispositivo IoT, calcular IoT_T_j, y gestionar variables CA_K.
    """
    global registered_devices, device_keys, IoT_Identity

    IoT_Identity = data.IoT_Identity
    DPUF_C1 = data.DPUF_C1
    FPUF_Fixed_F0 = data.FPUF_Fixed_F0
    FPUF_Fixed_F1 = data.FPUF_Fixed_F1

    # Verificar si el dispositivo ya está registrado
    if IoT_Identity in registered_devices:
        logger.warning(f"El dispositivo con ID {IoT_Identity} ya está registrado.")
        raise HTTPException(status_code=400, detail="El dispositivo ya está registrado.")

    logger.info(f"Recibidos datos del dispositivo IoT: IoT_Identity={IoT_Identity}, DPUF_C1={DPUF_C1}, FPUF_Fixed_F0={FPUF_Fixed_F0}, FPUF_Fixed_F1={FPUF_Fixed_F1}")

    # Cálculo de IoT_T_j
    IoT_T_j = K ^ FPUF_Fixed_F0 ^ FPUF_Fixed_F1

    # Generar variables CA_K específicas para este dispositivo
    CA_K_before_previous = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    CA_K_previous = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    CA_K_current = DPUF_C1  # Actualización con DPUF_C1 recibido

    # Registrar el dispositivo
    registered_devices.append(IoT_Identity)
    device_keys[IoT_Identity] = {
        "IoT_T_j": IoT_T_j,
        "CA_K_before_previous": CA_K_before_previous,
        "CA_K_previous": CA_K_previous,
        "CA_K_current": CA_K_current,
    }

    logger.info(f"Dispositivo IoT con ID {IoT_Identity} registrado exitosamente.")
    logger.info(f"Claves asociadas: {device_keys[IoT_Identity]}")
    
    # Respuesta al dispositivo IoT
    return IoTRegistrationResponse(CA_K_previous=CA_K_previous, IoT_T_j=IoT_T_j)

@app.get("/registration/devices")
async def listRegisteredDevices():
    """
    Endpoint para listar todas las identidades de sensores registrados.
    """
    logger.info("Listando dispositivos registrados.")
    return {"registered_devices": registered_devices}

@app.get("/registration/device/{iot_identity}")
async def getDeviceInfo(iot_identity: int):
    """
    Endpoint para obtener las claves asociadas con un dispositivo específico.
    """
    if iot_identity not in registered_devices:
        logger.warning(f"Intento de acceso a dispositivo no registrado con ID {iot_identity}.")
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado.")
    
    logger.info(f"Recuperando información para el dispositivo con ID {iot_identity}.")
    return device_keys[iot_identity]

#######################################################
#                   REGISTRO GATEWAY                  #
#######################################################

# Definir un modelo de datos para el registro del Gateway
class GatewayRegistrationRequest(BaseModel):
    Gateway_Identity: int
    
@app.post("/registration/gateway")
async def registerGateway(data: GatewayRegistrationRequest):
    """
    Registrar el gateway y devolver los parámetros necesarios.
    """
    global registered_gateways, gateway_keys, Gateway_Identity
    
    Gateway_Identity = data.Gateway_Identity

    # Generar parámetros específicos para el gateway
    CA_MK_G_CA = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    CA_Sync_K_G_CA_previous = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    CA_r_1_previous = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    CA_Sync_K_G_CA = Hash(CA_Sync_K_G_CA_previous, CA_r_1_previous)
    
    # Registrar el gateway
    registered_gateways.append(Gateway_Identity)

    gateway_keys[Gateway_Identity] = {
        "CA_MK_G_CA": CA_MK_G_CA,
        "CA_Sync_K_G_CA_previous": CA_Sync_K_G_CA_previous,
        "CA_r_1_previous": CA_r_1_previous,
        "CA_Sync_K_G_CA": CA_Sync_K_G_CA
    }

    logger.info(f"Gateway con ID {Gateway_Identity} registrado exitosamente.")
    logger.info(f"Claves asociadas: {gateway_keys[Gateway_Identity]}")

    # Retornar los parámetros al gateway
    return {"CA_Identity": CA_Identity, 
            "CA_MK_G_CA": CA_MK_G_CA,
            "CA_Sync_K_G_CA_previous": CA_Sync_K_G_CA_previous,
            "CA_r_1_previous": CA_r_1_previous}
    
#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################

def handleMutualAuthentication(gateway_socket):
    """
    Autenticación mutua del Gateway con la CA.
    """
    try:
        # Paso 1: Recibir datos del Gateway
        data = gateway_socket.recv(4096)
        data = json.loads(data.decode('utf-8'))

        # Realizar cálculos y preparar respuesta
        ReturnData = RetrieveR_2_ID(data)
        message = ReturnData[:6]
        HashResult = ReturnData[6]
        G_r_1_Decrypted = ReturnData[7]
        iv = ReturnData[8]
    
        # Paso 2: Enviar el mensaje (CA_sigma_3, Epison_2_1, ..., D_sync_CA_G) al Gateway
        response_payload = {
            "CA_sigma_3": message[0],
            "Epison_2_1": message[1],
            "Epison_2_2": message[2],
            "Epison_2_3": message[3],
            "Epison_2_4": message[4],
            "D_sync_CA_G": message[5],
        }
        gateway_socket.sendall(json.dumps(response_payload).encode('utf-8'))
        logger.info("Enviado mensaje de sincronización al Gateway.")

        # Paso 3: Recibir Epison_3_1 del Gateway
        data = gateway_socket.recv(4096)
        data = json.loads(data.decode('utf-8'))
        if "Epison_3_1" not in data:
            raise KeyError("Falta Epison_3_1 en la solicitud del Gateway.")
        Epison_3_1 = data["Epison_3_1"]
        logger.info("Recibido Epison_3_1 del Gateway.") 
        
        # Actualizar las claves de sincronización
        CA_K_before_previous = device_keys[IoT_Identity]["CA_K_before_previous"]
        CA_K_previous = device_keys[IoT_Identity]["CA_K_previous"]
        CA_K_current = device_keys[IoT_Identity]["CA_K_current"]
        CA_Sync_K_G_CA = registered_gateways[Gateway_Identity]["CA_Sync_K_G_CA"]

        M_3 = updatingSynchronizationKeys(
            Gateway_Identity,
            Epison_3_1,
            HashResult,
            iv,
            G_r_1_Decrypted,
            CA_K_previous,
            CA_K_current,
            CA_Sync_K_G_CA
        )
        logger.info("Claves de sincronización actualizadas correctamente.")

        # Paso 4: Enviar M_4 al Gateway
        gateway_socket.sendall(json.dumps({"M_3": M_3}).encode('utf-8'))
        logger.info("Mensaje M_3 enviado al Gateway.")
        
    except KeyError as e:
        logger.error(f"Clave faltante en los datos recibidos: {e}")
    except Exception as e:
        logger.error(f"Error durante la autenticación mutua: {e}")
    finally:
        gateway_socket.close()
    
def RetrieveR_2_ID(data):
    Gateway_Identity= data[0]
    G_nonce= data[1]
    G_sigma_1= data[2]
    G_sigma_2= data[3]
    Epison_1_1= data[4]
    Epison_1_2= data[5]
    Epison_1_3= data[6]
    Epison_1_4= data[7]
    Epison_1_5= data[8]
    iv= data[9]

    # Datos del registro del gateway
    CA_MK_G_CA = registered_gateways[Gateway_Identity]["CA_MK_G_CA"]
    CA_Sync_K_G_CA_previous = registered_gateways[Gateway_Identity]["CA_Sync_K_G_CA_previous"]
    CA_Sync_K_G_CA = registered_gateways[Gateway_Identity]["CA_Sync_K_G_CA"]
    
    h1 = hashlib.new('sha256')
    h1.update(CA_Sync_K_G_CA.to_bytes(32, 'big'))
    HashResult=bytes(h1.hexdigest(),'utf-8')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_ID_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_1), 'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_r_2_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_2),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_r_3_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_3),'big')
        
    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_r_1_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_4),'big')

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_K_i_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_5),'big')
   
    assert G_sigma_1 ==Hash(CA_MK_G_CA,Gateway_Identity,G_nonce), "The authentication of the Gateway by the CA has failed"

    if G_sigma_2==Hash(CA_Sync_K_G_CA_previous,Gateway_Identity,G_nonce):
        D_sync_CA_G=1 #it was -1
    elif G_sigma_2 == Hash(CA_Sync_K_G_CA,Gateway_Identity,G_nonce):
        D_sync_CA_G=0
    CA_r_2_retrieved=IoT_r_2_Decrypted^K

    CA_IoT_ID_retrieved=IoT_ID_Decrypted^Hash(G_r_1_Decrypted,CA_r_2_retrieved)
    CA_sigma_3=Hash(CA_MK_G_CA,CA_Identity,D_sync_CA_G,G_nonce+1)

    # Datos del registro del IoT
    CA_K_before_previous = device_keys[IoT_Identity]["CA_K_before_previous"]
    CA_K_previous = device_keys[IoT_Identity]["CA_K_previous"]
    CA_K_current = device_keys[IoT_Identity]["CA_K_current"]
    CA_r_1_previous = device_keys[IoT_Identity]["CA_r_1_previous"]
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_1=ENC.encrypt(CA_K_before_previous.to_bytes(4,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_2=ENC.encrypt(CA_K_previous.to_bytes(4,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_3=ENC.encrypt(CA_K_current.to_bytes(4,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_4=ENC.encrypt(CA_r_1_previous.to_bytes(4,'big'))

    return CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G, HashResult, G_r_1_Decrypted, iv

def updatingSynchronizationKeys(Gateway_Identity,Epison_3_1,HashResult,iv,G_r_1_Decrypted,CA_K_previous,CA_K_current,CA_Sync_K_G_CA):
        
    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    CA_IoT_K_i_next=int.from_bytes(DEC.decrypt(Epison_3_1),'big')

    ##### Update the IoT synchronization keys ##############
    
    device_keys[IoT_Identity]["CA_K_before_previous"]=CA_K_previous
    device_keys[IoT_Identity]["CA_K_previous"]=CA_K_current
    device_keys[IoT_Identity]["CA_K_current"]=CA_IoT_K_i_next
    device_keys[IoT_Identity]["CA_r_1_previous"]=G_r_1_Decrypted
    
    CA_K_before_previous=device_keys[IoT_Identity]["CA_K_before_previous"]
    CA_K_previous= device_keys[IoT_Identity]["CA_K_previous"]
    CA_K_current=device_keys[IoT_Identity]["CA_K_current"]
    
    ##### Update the gateway & CA synchronization keys ###########
    CA_Sync_K_G_CA_previous=CA_Sync_K_G_CA
    CA_Sync_K_G_CA=Hash(CA_Sync_K_G_CA,G_r_1_Decrypted)
    M_3=Hash(CA_K_before_previous,CA_K_previous,CA_K_current,CA_Sync_K_G_CA)
    registered_gateways[Gateway_Identity]["CA_Sync_K_G_CA_previous"] = CA_Sync_K_G_CA_previous
    return M_3

if __name__ == "__main__":
    #logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8011.")
    #start_http_server(8011, addr="0.0.0.0")
    uvicorn.run(app, host="0.0.0.0", port=8001)
    logger.info("API del Cloud Admin iniciada.")
    #startCloudServer()