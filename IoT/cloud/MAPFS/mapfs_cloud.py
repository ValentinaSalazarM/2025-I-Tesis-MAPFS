from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/MAPFS-cloud.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Cloud")

# Configuración del servidor socket para que acepte conexiones desde otros contenedores
HOST = "0.0.0.0"
PORT = 5001

# Lista global para almacenar los sensores registrados
registered_devices = []

# Lista global para almacenar los gateways registrados
registered_gateways = []

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
        server_socket.listen(5)
        logger.info(f"Servidor Cloud escuchando en {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            logger.info(f"Conexión aceptada de {addr}")
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
        # Enviar parámetros públicos al dispositivo
        payload_public_keys["operation"] = "register"
        public_parameters = encode_message(payload_public_keys)
        client_socket.sendall(json.dumps(public_parameters).encode("utf-8"))
        logger.info(
            f"[REG Dispositivo] Enviar parámetros públicos: {public_parameters}"
        )

        # Paso 1: Generación de las llaves del dispositivo
        y_a_priv_key, Y_a_pub_key = keys.gen_keypair(P256)

        # Paso 2: Recibir IoT_identity, X_a_pub_key, h_x del dispositivo
        first_request = client_socket.recv(4096)
        first_message = decode_message(json.loads(first_request.decode("utf-8")))

        iot_identity = first_message.get("IoT_Identity")
        X_a_pub_key_dict = first_message.get("X_a_pub_key")
        h_x_dict = first_message.get("h_x")

        # Verificar si el dispositivo ya está registrado
        if iot_identity in registered_devices:
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

        # Paso 3: Registrar el dispositivo
        registered_devices.append(iot_identity)

        device_keys = {
            "X_a_pub_key": X_a_pub_key_dict,
            "Y_a_pub_key": Y_a_pub_key_dict,
            "y_a_priv_key": y_a_priv_key,
            "h_a": h_a,
            "h_x": h_x_dict,
        }

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
    except ValueError as e:
        logger.error(f"Error en el registro del dispositivo IoT: {e}")
        client_socket.sendall(
            json.dumps(encode_message({"error": str(e)})).encode("utf-8")
        )
    except Exception as e:
        logger.error(f"Error inesperado durante el registro del dispositivo IoT: {e}")
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
        # Enviar parámetros públicos al gateway
        payload_public_keys["operation"] = "register"
        public_parameters = encode_message(payload_public_keys)
        client_socket.sendall(json.dumps(public_parameters).encode("utf-8"))
        logger.info(f"[REG Gateway] Enviar parámetros públicos: {public_parameters}")

        # Paso 1: Generación de las llaves del gateway
        y_w_priv_key, Y_w_pub_key = keys.gen_keypair(P256)

        # Paso 2: Recibir Gateway_Identity, X_w_pub_key del gateway
        first_response = client_socket.recv(4096)
        first_message = json.loads(first_response.decode("utf-8"))

        gateway_identity = first_message.get("Gateway_Identity")
        X_w_pub_key_dict = first_message.get("X_w_pub_key")

        # Verificar si el gateway ya está registrado
        if gateway_identity in registered_gateways:
            logger.warning(
                f"[REG Gateway] El gateway con ID {gateway_identity} ya está registrado."
            )
            raise ValueError("El gateway ya está registrado.")

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

        # Paso 3: Registrar el gateway
        registered_gateways.append(gateway_identity)
        gateway_keys = {
            "X_w_pub_key": X_w_pub_key_dict,
            "Y_w_pub_key": Y_w_pub_key_dict,
            "y_w_priv_key": y_w_priv_key,
            "h_w": h_w,
        }

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
        logger.error(f"Clave faltante en los datos del gateway: {e}")
    except ValueError as e:
        logger.error(f"Error en el registro del gateway: {e}")
        client_socket.sendall(
            json.dumps(encode_message({"error": str(e)})).encode("utf-8")
        )
    except Exception as e:
        logger.error(f"Error inesperado durante el registro del gateway: {e}")
    finally:
        client_socket.close()
        logger.info("[REG Gateway] Conexión con el gateway cerrada.")


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
    # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8011.")
    start_http_server(8011, addr="0.0.0.0")
    # Inicia el socket
    start_cloud_socket()
