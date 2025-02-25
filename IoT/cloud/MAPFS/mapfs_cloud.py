from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="MAPFS time=%(asctime)s level=%(levelname)s msg=\'%(message)s\'",
    handlers=[logging.FileHandler("/logs/MAPFS-cloud.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Cloud")

# Configuración del servidor socket para que acepte conexiones desde otros contenedores
HOST = "0.0.0.0"
PORT = 5001

# Puerto del Gateway
REVOCATION_PORT = 6000

# Diccionario para almacenar los sensores registrados
registered_devices = {}

# Diccionario para almacenar los gateways registrados
registered_gateways = {}

# Selecciona su llave secreta y su par público
s_gc_priv_key, Pub_gc_key = keys.gen_keypair(P256)
s_IoT_priv_key, P_IoT_key = keys.gen_keypair(P256)

Pub_gc_key_xValue = Pub_gc_key.x
Pub_gc_key_yValue = Pub_gc_key.y

P_IoT_key_xValue = P_IoT_key.x
P_IoT_key_yValue = P_IoT_key.y

payload_public_keys = {
    "Pub_gc_key": {"x": Pub_gc_key_xValue, "y": Pub_gc_key_yValue},
    "P_IoT_key": {"x": P_IoT_key_xValue, "y": P_IoT_key_yValue},
}

#######################################################
#                   INICIAR SERVIDOR                  #
#######################################################


def start_cloud_socket():
    """
    Inicia el servidor socket para manejar conexiones del Gateway y del Device.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logger.info(f"Servidor Cloud escuchando en {HOST}:{PORT}")

        while True:
            client_socket, clt_address = server_socket.accept()
            logger.info(f"Conexión aceptada de {clt_address}")
            handle_client_connection(client_socket)


def handle_client_connection(client_socket):
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
        message = decode_message(json.loads(data.decode("utf-8")))
        logger.info(f"Mensaje recibido: {message}")

        # Verificar el tipo de operación
        operation = message.get("operation")
        if not operation:
            raise ValueError("Falta el campo 'operation' en el mensaje recibido.")

        # Redirigir a la función correspondiente
        if operation == "register_gateway":
            handle_gateway_registration(client_socket)
        elif operation == "register_device":
            handle_IoT_registration(client_socket)
        elif operation == "identify_and_revoke":
            handle_id_revocation(client_socket, message)
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


def handle_IoT_registration(client_socket):
    """
    Manejar el registro del dispositivo IoT.
    """
    global registered_devices, payload_public_keys, Pub_gc_key_xValue, Pub_gc_key_yValue, P_IoT_key_xValue, P_IoT_key_yValue

    try:
        client_ip, client_port = client_socket.getpeername()

        # Enviar parámetros públicos al dispositivo
        payload_public_keys["operation"] = "register"
        public_parameters = encode_message(payload_public_keys)
        client_socket.sendall(json.dumps(public_parameters).encode("utf-8"))
        logger.info(
            f"[REG Dispositivo] Enviar parámetros públicos: {public_parameters}"
        )

        # Generación de las llaves del dispositivo
        y_a_priv_key, Y_a_pub_key = keys.gen_keypair(P256)

        # Recibir IoT_identity, X_a_pub_key, h_x del dispositivo
        first_request = client_socket.recv(4096)
        first_message = decode_message(json.loads(first_request.decode("utf-8")))

        iot_identity = first_message.get("IoT_Identity")
        X_a_pub_key_dict = first_message.get("X_a_pub_key")
        h_x_dict = first_message.get("h_x")

        # Verificar si el dispositivo ya está registrado
        if iot_identity in registered_devices.keys():
            logger.warning(
                f"[REG Dispositivo] El dispositivo con ID {iot_identity} ya está registrado."
            )
            raise ValueError("El dispositivo ya está registrado.")

        logger.info(
            f"[REG Dispositivo] Recibidos datos del dispositivo IoT: IoT_Identity={iot_identity}, X_a_pub_key={X_a_pub_key_dict}, h_x={h_x_dict}"
        )

        # Generar los valores de las claves públicas como bytes
        X_a_pub_key_xValue = X_a_pub_key_dict.get("x")
        X_a_pub_key_yValue = X_a_pub_key_dict.get("y")

        Y_a_pub_key_xValue = Y_a_pub_key.x
        Y_a_pub_key_yValue = Y_a_pub_key.y
        Y_a_pub_key_dict = {"x": Y_a_pub_key_xValue, "y": Y_a_pub_key_yValue}

        h_a = Hash_MAPFS(
            [
                X_a_pub_key_xValue,
                X_a_pub_key_yValue,
                Y_a_pub_key_xValue,
                Y_a_pub_key_yValue,
                Pub_gc_key_xValue,
                Pub_gc_key_yValue,
            ]
        )

        sigma_a = (s_IoT_priv_key + h_a * y_a_priv_key + y_a_priv_key) % P256.q

        # Registrar el dispositivo

        device_keys = {
            "IP": client_ip,
            "X_a_pub_key": X_a_pub_key_dict,
            "Y_a_pub_key": Y_a_pub_key_dict,
            "y_a_priv_key": y_a_priv_key,
            "h_a": h_a,
            "h_x": h_x_dict,
        }

        registered_devices[iot_identity] = device_keys

        logger.info(
            f"[REG Dispositivo] Dispositivo IoT con ID {iot_identity} registrado exitosamente. Claves asociadas: {device_keys}"
        )

        # Enviar sigma_a, Y_a_pub_key y h_a al dispositivo
        response = {
            "operation": "register",
            "sigma_a": sigma_a,
            "Y_a_pub_key": Y_a_pub_key_dict,
            "h_a": h_a,
        }
        encoded_response = encode_message(response)
        client_socket.sendall(json.dumps(encoded_response).encode("utf-8"))
        logger.info("[REG Dispositivo] Respuesta enviada al dispositivo IoT.")

    except KeyError as e:
        logger.error(f"Clave faltante en los datos del dispositivo IoT: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except ValueError as e:
        logger.error(f"Error en el registro del dispositivo IoT: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"Error inesperado durante el registro del dispositivo IoT: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    finally:
        client_socket.close()
        logger.info("[REG Dispositivo] Conexión con el dispositivo IoT cerrada.")


#######################################################
#                   REGISTRO GATEWAY                  #
#######################################################


def handle_gateway_registration(client_socket):
    """
    Manejar el registro del Gateway.
    """
    global registered_gateways, payload_public_keys, Pub_gc_key_xValue, Pub_gc_key_yValue, P_IoT_key_xValue, P_IoT_key_yValue

    try:
        client_ip, client_port = client_socket.getpeername()

        # Enviar parámetros públicos al gateway
        payload_public_keys["operation"] = "register"
        public_parameters = encode_message(payload_public_keys)
        client_socket.sendall(json.dumps(public_parameters).encode("utf-8"))
        logger.info(f"[REG Gateway] Enviar parámetros públicos: {public_parameters}")

        # Generación de las llaves del gateway
        y_w_priv_key, Y_w_pub_key = keys.gen_keypair(P256)

        # Recibir Gateway_Identity, X_w_pub_key del gateway
        first_response = client_socket.recv(4096)
        first_message = json.loads(first_response.decode("utf-8"))

        gateway_identity = first_message.get("Gateway_Identity")
        X_w_pub_key_dict = first_message.get("X_w_pub_key")

        # Verificar si el gateway ya está registrado
        if gateway_identity in registered_gateways:
            logger.warning(
                f"[REG Gateway] El gateway con ID {gateway_identity} ya se encuentra registrado."
            )
            raise ValueError("El gateway ya se encuentra registrado.")

        logger.info(
            f"[REG Gateway] Recibidos datos del gateway: Gateway_Identity={gateway_identity}, X_w_pub_key={X_w_pub_key_dict}"
        )

        # Generar los valores de las claves públicas como bytes
        X_w_pub_key_xValue = X_w_pub_key_dict.get("x")
        X_w_pub_key_yValue = X_w_pub_key_dict.get("y")

        Y_w_pub_key_xValue = Y_w_pub_key.x
        Y_w_pub_key_yValue = Y_w_pub_key.y
        Y_w_pub_key_dict = {"x": Y_w_pub_key_xValue, "y": Y_w_pub_key_yValue}

        h_w = Hash_MAPFS(
            [
                X_w_pub_key_xValue,
                X_w_pub_key_yValue,
                Pub_gc_key_xValue,
                Pub_gc_key_yValue,
                Y_w_pub_key_xValue,
                Y_w_pub_key_yValue,
            ]
        )
        sigma_w = (s_gc_priv_key + h_w * y_w_priv_key) % P256.q

        # Registrar el gateway
        gateway_keys = {
            "IP": client_ip,
            "X_w_pub_key": X_w_pub_key_dict,
            "Y_w_pub_key": Y_w_pub_key_dict,
            "y_w_priv_key": y_w_priv_key,
            "h_w": h_w,
        }

        registered_gateways[gateway_identity] = gateway_keys

        logger.info(
            f"[REG Gateway] Gateway con ID {gateway_identity} registrado exitosamente. Claves asociadas: {gateway_keys}"
        )

        # Enviar sigma_w, Y_w_pub_key y h_w al gateway
        response = {
            "operation": "register",
            "sigma_w": sigma_w,
            "Y_w_pub_key": Y_w_pub_key_dict,
            "h_w": h_w,
        }
        encoded_response = encode_message(response)
        client_socket.sendall(json.dumps(encoded_response).encode("utf-8"))
        logger.info("[REG Gateway] Respuesta enviada al gateway.")

    except KeyError as e:
        logger.error(f"Clave faltante en los datos del Gateway: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except ValueError as e:
        logger.error(f"Error en el registro del Gateway: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"Error inesperado durante el registro del Gateway: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    finally:
        client_socket.close()
        logger.info("[REG Gateway] Conexión con el Gateway cerrada.")


#######################################################
#                 REVOCAR IDENTIDADES                 #
#######################################################


def handle_id_revocation(client_socket, message):
    """
    Maneja la revocación de un dispositivo IoT reportado como malicioso por un Gateway.
    """
    global registered_devices, registered_gateways

    try:
        # Validar que los parámetros de P_1 y P_3 existen en el mensaje
        if "P_1" not in message or "P_3" not in message:
            raise ValueError("Faltan los parámetros P_1 o P_3 en la solicitud.")

        P_1_dict = message["P_1"]
        P_3_dict = message["P_3"]

        # Convertir los puntos a la curva elíptica
        P_1 = Point(P_1_dict["x"], P_1_dict["y"], curve=P256)
        P_3 = Point(P_3_dict["x"], P_3_dict["y"], curve=P256)

        misbehaving_iot = None
        parameters = {}

        # Búsqueda en la base de datos de dispositivos registrados
        for iot_identity, device_data in registered_devices.items():
            h_a = device_data.get("h_a")

            # Verificar si el dispositivo cumple con la condición P_3 = h_a * P_1
            if P_3 == h_a * P_1:
                misbehaving_iot = iot_identity
                parameters = device_data
                break

        if not misbehaving_iot:
            logger.warning(
                "[REVOC] No se encontró un dispositivo que cumpla con la condición P_3 = h_a * P_1."
            )
            raise ValueError("Los P_1 o P_3 son incorrectos.")

        logger.info(
            f"[REVOC] Dispositivo identificado para revocación: {misbehaving_iot}"
        )

        response = {
            "status": "success",
            "message": "Métricas recibidas correctamente.",
        }
        client_socket.sendall(json.dumps(response).encode("utf-8"))
        
        # Crear el payload para enviar a los Gateways
        payload = {
            "operation": "identify_and_revoke",
            "ID_a": misbehaving_iot,
            "X_a_pub_key": parameters.get("X_a_pub_key"),
            "Y_a_pub_key": parameters.get("Y_a_pub_key"),
            "h_a": parameters.get("h_a"),
            "P_1": P_1_dict,
            "P_3": P_3_dict,
        }

        # Enviar el mensaje de revocación a todos los Gateways
        for gateway_identity, gateway_data in registered_gateways.items():
            gateway_ip = gateway_data.get("IP")

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    logger.info(
                        f"[REVOC] Conectando a Gateway en {gateway_ip}:{REVOCATION_PORT}."
                    )
                    s.connect((gateway_ip, REVOCATION_PORT))

                    # Enviar mensaje en formato JSON
                    s.sendall(json.dumps(payload).encode())

                    # Recibir respuesta del Gateway
                    response = s.recv(1024).decode()
                    logger.info(f"[REVOC] Respuesta de {gateway_ip}: {response}")

            except Exception as e:
                logger.error(f"[REVOC] Error al conectar con {gateway_ip}: {e}")
    
    except ValueError as e:
        logger.error(f"[REVOC] Error en el mensaje recibido: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"[REVOC] Error inesperado durante la revocación: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))


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
            encoded_message[key] = base64.b64encode(value).decode(
                "utf-8"
            )  # Convertir bytes a base64 y luego a str
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
                if base64.b64encode(base64.b64decode(value)).decode("utf-8") == value:
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
    time.sleep(5)
    os.makedirs("../../Logs/", mode=0o777, exist_ok=True)
    
    # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8011.")
    start_http_server(8011, addr="0.0.0.0")
    
    
    # Inicia el socket
    start_cloud_socket()
