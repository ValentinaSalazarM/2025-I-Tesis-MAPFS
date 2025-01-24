import binascii
import requests
import logging
import socket
import base64
import json
import os
import threading

from common.cripto_primitivas import *

from prometheus_client import start_http_server, Counter

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
#                 INICIAR SERVIDORES                  #
#######################################################

def startSocket():
    """
    Inicia el servidor socket para manejar conexiones del Gateway y del Device.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logger.info(f"Servidor Cloud escuchando en {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            logger.info(f"Conexión aceptada de {addr}")
            handleClientConnection(client_socket)

def handleClientConnection(client_socket):
    """
    Maneja las conexiones entrantes y redirige a la función adecuada.
    """
    try:
        # Recibir datos del cliente
        data = client_socket.recv(4096)
        if not data:
            logger.error("No se recibieron datos del cliente.")
            return

        # Decodificar el mensaje
        message = decode_message(json.loads(data.decode('utf-8')))
        logger.info(f"Mensaje recibido: {message}")

        # Verificar el tipo de operación
        operation = message.get("operation")
        if not operation:
            raise ValueError("Falta el campo 'operation' en el mensaje recibido.")

        # Redirigir a la función correspondiente
        if operation == "register_gateway":
            handleGatewayRegistration(client_socket, message)
        elif operation == "register_device":
            handleIoTRegistration(client_socket, message)
        elif operation == "mutual_authentication":
            handleMutualAuthentication(client_socket, message)
        else:
            raise ValueError(f"Operación desconocida: {operation}")

    except ValueError as e:
        logger.error(f"Error en el mensaje recibido: {e}")
    except Exception as e:
        logger.error(f"Error durante el manejo de la conexión: {e}")
    finally:
        client_socket.close()
        logger.info("Conexión con el cliente cerrada.")


#######################################################
#              REGISTRO DISPOSITIVO IOT               #
#######################################################

def handleIoTRegistration(client_socket, message):
    """
    Manejar el registro del dispositivo IoT.
    """
    global registered_devices, device_keys, IoT_Identity

    try:
        logger.info("[REG Dispositivo] Enviando desafíos C_F0 y C_F1 al dispositivo IoT.")
        
        # Enviar los desafíos al dispositivo
        challenges = {"C_F0": C_F0, "C_F1": C_F1}
        client_socket.sendall(json.dumps(encode_message(challenges)).encode('utf-8'))

        # Recibir datos del dispositivo IoT
        data = client_socket.recv(4096)
        if not data:
            logger.error("[REG Dispositivo] No se recibieron datos del dispositivo IoT.")
            return

        # Decodificar mensaje
        message = decode_message(json.loads(data.decode('utf-8')))
        logger.info(f"[REG Dispositivo] Mensaje recibido del dispositivo IoT: {message}")

        # Validar los datos recibidos
        IoT_Identity = message.get("IoT_Identity")
        DPUF_C1 = message.get("DPUF_C1")
        FPUF_Fixed_F0 = message.get("FPUF_Fixed_F0")
        FPUF_Fixed_F1 = message.get("FPUF_Fixed_F1")

        if None in (IoT_Identity, DPUF_C1, FPUF_Fixed_F0, FPUF_Fixed_F1):
            raise KeyError("Faltan datos en el mensaje recibido para el registro del dispositivo IoT.")

        # Verificar si el dispositivo ya está registrado
        if IoT_Identity in registered_devices:
            logger.warning(f"[REG Dispositivo] El dispositivo con ID {IoT_Identity} ya está registrado.")
            raise ValueError("El dispositivo ya está registrado.")

        logger.info(f"[REG Dispositivo] Recibidos datos del dispositivo IoT: IoT_Identity={IoT_Identity}, DPUF_C1={DPUF_C1}, FPUF_Fixed_F0={FPUF_Fixed_F0}, FPUF_Fixed_F1={FPUF_Fixed_F1}")

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

        logger.info(f"[REG Dispositivo] Dispositivo IoT con ID {IoT_Identity} registrado exitosamente. Claves asociadas: {device_keys[IoT_Identity]}")

        # Preparar y enviar la respuesta al dispositivo IoT
        response = {
            "CA_K_previous": CA_K_previous,
            "IoT_T_j": IoT_T_j
        }
        encoded_response = encode_message(response)
        client_socket.sendall(json.dumps(encoded_response).encode('utf-8'))
        logger.info("[REG Dispositivo] Respuesta enviada al dispositivo IoT.")

    except KeyError as e:
        logger.error(f"Clave faltante en los datos del dispositivo IoT: {e}")
    except ValueError as e:
        logger.error(f"Error en el registro del dispositivo IoT: {e}")
        client_socket.sendall(json.dumps(encode_message({"error": str(e)})).encode('utf-8'))
    except Exception as e:
        logger.error(f"Error inesperado durante el registro del dispositivo IoT: {e}")
    finally:
        client_socket.close()
        logger.info("[REG Dispositivo] Conexión con el dispositivo IoT cerrada.")


#######################################################
#                   REGISTRO GATEWAY                  #
#######################################################

def handleGatewayRegistration(client_socket, message):
    """
    Manejar el registro del Gateway.
    """
    try:
        Gateway_Identity = message.get("Gateway_Identity")
        if not Gateway_Identity:
            raise KeyError("Falta Gateway_Identity en el mensaje recibido.")

        # Registrar el Gateway
        response = registerGateway(message)

        # Codificar y enviar respuesta al Gateway
        encoded_response = encode_message(response)
        client_socket.sendall(json.dumps(encoded_response).encode('utf-8'))
        logger.info(f"Gateway registrado con éxito: {Gateway_Identity}")

    except KeyError as e:
        logger.error(f"Clave faltante: {e}")
    except Exception as e:
        logger.error(f"Error durante el registro del Gateway: {e}")
        
def registerGateway(message):
    """
    Registrar el gateway y devolver los parámetros necesarios.
    """
    global registered_gateways, gateway_keys, Gateway_Identity
    
    Gateway_Identity = message["Gateway_Identity"]

    # Generar parámetros específicos para el gateway
    CA_MK_G_CA = int.from_bytes(os.urandom(1024), 'big') % 90000 + 10000  
    CA_Sync_K_G_CA_previous = int.from_bytes(os.urandom(1024), 'big')% 90000 + 10000  
    CA_r_1_previous = int.from_bytes(os.urandom(1024), 'big')% 90000 + 10000  
    CA_Sync_K_G_CA = Hash(CA_Sync_K_G_CA_previous, CA_r_1_previous)
    
    # Registrar el gateway
    registered_gateways.append(Gateway_Identity)

    gateway_keys[Gateway_Identity] = {
        "CA_MK_G_CA": CA_MK_G_CA,
        "CA_Sync_K_G_CA_previous": CA_Sync_K_G_CA_previous,
        "CA_r_1_previous": CA_r_1_previous,
        "CA_Sync_K_G_CA": CA_Sync_K_G_CA
    }

    logger.info(f"[REG Gateway] Gateway con ID {Gateway_Identity} registrado exitosamente. Claves asociadas: {gateway_keys[Gateway_Identity]}")

    # Retornar los parámetros al gateway
    return {"CA_Identity": CA_Identity, 
            "CA_MK_G_CA": CA_MK_G_CA,
            "CA_Sync_K_G_CA_previous": CA_Sync_K_G_CA_previous,
            "CA_r_1_previous": CA_r_1_previous}
    
#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################

def handleMutualAuthentication(gateway_socket, decoded_message):
    """
    Autenticación mutua del Gateway con la CA.
    """
    try:
        # Paso 1: Recibir datos del Gateway
        logger.info(f"[AUTH] Recepción de datos del Gateway: {decoded_message}.")
        
        ReturnData = RetrieveR_2_ID(decoded_message)
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
        encoded_message = encode_message(response_payload)
        gateway_socket.sendall(json.dumps(encoded_message).encode('utf-8'))
        logger.info("[AUTH] Enviado mensaje de sincronización al Gateway.")

        # Paso 3: Recibir Epison_3_1 del Gateway
        data = gateway_socket.recv(4096)
        received_message = json.loads(data.decode('utf-8'))
        decoded_message = decode_message(received_message)
        if "Epison_3_1" not in decoded_message:
            raise KeyError("Falta Epison_3_1 en la solicitud del Gateway.")
        Epison_3_1 = decoded_message["Epison_3_1"]
        logger.info("[AUTH] Recibido Epison_3_1 del Gateway.") 
        
        # Actualizar las claves de sincronización
        CA_K_previous = device_keys[IoT_Identity]["CA_K_previous"]
        CA_K_current = device_keys[IoT_Identity]["CA_K_current"]
        CA_Sync_K_G_CA = gateway_keys[Gateway_Identity]["CA_Sync_K_G_CA"]
        
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
        logger.info("[AUTH] Claves de sincronización actualizadas correctamente.")

        # Paso 4: Enviar M_3 al Gateway
        encoded_message = encode_message({"M_3": M_3})
        gateway_socket.sendall(json.dumps(encoded_message).encode('utf-8'))
        logger.info("[AUTH] Mensaje M_3 enviado al Gateway.")
        logger.info("[AUTH] Autenticación mutua culminada.")
    except KeyError as e:
        logger.error(f"Clave faltante en los datos recibidos: {e}")
    except Exception as e:
        logger.error(f"Error durante la autenticación mutua: {e}")
    finally:
        gateway_socket.close()
    
def RetrieveR_2_ID(data):
    G_nonce= data["G_nonce"]
    G_sigma_1= data["G_sigma_1"]
    G_sigma_2= data["G_sigma_2"]
    Epison_1_1= data["Epison_1_1"]
    Epison_1_2= data["Epison_1_2"]
    Epison_1_3= data["Epison_1_3"]
    Epison_1_4= data["Epison_1_4"]
    Epison_1_5= data["Epison_1_5"]
    iv= data["iv"]
  
    # Datos del registro del gateway
    CA_MK_G_CA = gateway_keys[Gateway_Identity]["CA_MK_G_CA"]
    CA_Sync_K_G_CA_previous = gateway_keys[Gateway_Identity]["CA_Sync_K_G_CA_previous"]
    CA_Sync_K_G_CA = gateway_keys[Gateway_Identity]["CA_Sync_K_G_CA"]

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
    
    # Datos del registro del Gateway
    CA_r_1_previous = gateway_keys[Gateway_Identity]["CA_r_1_previous"]
    
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_1=ENC.encrypt(CA_K_before_previous.to_bytes(32,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_2=ENC.encrypt(CA_K_previous.to_bytes(32,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_3=ENC.encrypt(CA_K_current.to_bytes(32,'big'))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_4=ENC.encrypt(CA_r_1_previous.to_bytes(32,'big'))

    return CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G, HashResult, G_r_1_Decrypted, iv

def updatingSynchronizationKeys(Gateway_Identity,Epison_3_1,HashResult,iv,G_r_1_Decrypted,CA_K_previous,CA_K_current,CA_Sync_K_G_CA):
        
    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    CA_IoT_K_i_next=int.from_bytes(DEC.decrypt(Epison_3_1),'big')

    ##### Update the IoT synchronization keys ##############
    
    device_keys[IoT_Identity]["CA_K_before_previous"]=CA_K_previous
    device_keys[IoT_Identity]["CA_K_previous"]=CA_K_current
    device_keys[IoT_Identity]["CA_K_current"]=CA_IoT_K_i_next
    gateway_keys[Gateway_Identity]["CA_r_1_previous"]=G_r_1_Decrypted
    
    CA_K_before_previous=device_keys[IoT_Identity]["CA_K_before_previous"]
    CA_K_previous= device_keys[IoT_Identity]["CA_K_previous"]
    CA_K_current=device_keys[IoT_Identity]["CA_K_current"]
    
    ##### Update the gateway & CA synchronization keys ###########
    CA_Sync_K_G_CA_previous=CA_Sync_K_G_CA
    CA_Sync_K_G_CA=Hash(CA_Sync_K_G_CA,G_r_1_Decrypted)
    M_3=Hash(CA_K_before_previous,CA_K_previous,CA_K_current,CA_Sync_K_G_CA)
    gateway_keys[Gateway_Identity]["CA_Sync_K_G_CA_previous"] = CA_Sync_K_G_CA_previous
    return M_3

#######################################################
#                      AUXILIARES                     #
#######################################################

def encode_message(message_dict):
    """
    Convierte un mensaje en un formato JSON serializable.
    Los objetos de tipo bytes se codifican en base64.
    """
    encoded_message = {}
    
    # Recorre y codifica cada elemento del mensaje
    for key in message_dict:
        value = message_dict[key]
        if isinstance(value, bytes):
            encoded_message[key] = base64.b64encode(value).decode('utf-8')  # Convertir bytes a base64 y luego a str
        else:
            encoded_message[key] = value
    return encoded_message

def decode_message(encoded_message_dict):
    """
    Decodifica un mensaje que contiene valores codificados en Base64.
    """
    decoded_message = {}
    for key, value in encoded_message_dict.items():
        if isinstance(value, str):  # Solo intentar decodificar cadenas
            try:
                # Intentar decodificar si es válido Base64
                if base64.b64encode(base64.b64decode(value)).decode('utf-8') == value:
                    decoded_message[key] = base64.b64decode(value)
                else:
                    decoded_message[key] = value
            except (ValueError, binascii.Error):
                # Si no es Base64, mantener el valor original
                decoded_message[key] = value
        else:
            # No es cadena, mantener el valor original
            decoded_message[key] = value
    return decoded_message


if __name__ == "__main__":
    # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8011.")
    start_http_server(8011, addr="0.0.0.0")

    # Crear hilos para la API y el servidor de sockets
    # api_thread = threading.Thread(target=startApiServer)
    socket_thread = threading.Thread(target=startSocket)

    # Iniciar ambos hilos
    #api_thread.start()
    socket_thread.start()

    # Esperar a que los hilos terminen
    #api_thread.join()
    socket_thread.join()