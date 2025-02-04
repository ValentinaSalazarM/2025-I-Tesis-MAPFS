from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/MAPFS-gateway.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Gateway")

# Configuración del servidor socket
HOST = "0.0.0.0"  # Dirección IP del Gateway
PORT = 5000  # Puerto del Gateway
CA_HOST = "mapfs-cloud"  # Dirección de la CA
CA_PORT = 5001  # Puerto de la CA
cloud_socket = None

# Parámetros publicados por el CA
Pub_gc_key_xValue = None
Pub_gc_key_yValue = None

P_IoT_key_xValue = None
P_IoT_key_yValue = None

# Parámetros de registro
registration_parameters = {}
gateway_identity = int.from_bytes(os.urandom(8), "big")

# Llaves de sesión con dispositivos IoT
session_keys = {}


#######################################################
#               SERVIDOR SOCKET GATEWAY               #
#######################################################
def start_gateway_socket():
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
        message = json.loads(data.decode("utf-8"))
        logger.info(f"Mensaje recibido: {message}")

        # Verificar el tipo de operación
        operation = message.get("operation")
        if not operation:
            raise ValueError("Falta el campo 'operation' en el mensaje recibido.")

        # Redirigir a la función correspondiente
        if operation == "mutual_authentication":
            handle_mutual_authentication(client_socket, message)
        elif operation == "send_metrics":
            handle_send_metrics(client_socket, message)
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
#                   REGISTRO GATEWAY                  #
#######################################################


def gateway_registration():
    global registration_parameters, gateway_identity, Pub_gc_key_xValue, Pub_gc_key_yValue, P_IoT_key_xValue, P_IoT_key_yValue

    try:
        # Inicializar el socket con el CA
        initialize_socket()

        # Paso 1: Enviar al CA la solicitud de registro
        first_payload = {"operation": "register_gateway"}
        logger.info("[REG] Enviada solicitud de registro al CA.")

        # Recibir parámetros públicos del CA
        first_response = send_and_receive_persistent_socket(first_payload)

        Pub_gc_key = first_response.get("Pub_gc_key")
        Pub_gc_key_xValue = Pub_gc_key.get("x")
        Pub_gc_key_yValue = Pub_gc_key.get("y")

        P_IoT_key = first_response.get("P_IoT_key")
        P_IoT_key_xValue = P_IoT_key.get("x")
        P_IoT_key_yValue = P_IoT_key.get("y")

        logger.info(f"[REG] Recibidos parámetros públicos del CA: {first_response}.")

        # Paso 2: Generación de las llaves del IoT y de su identidad
        x_w_priv_key, X_w_pub_key = keys.gen_keypair(P256)

        # Paso 3: Enviar al CA la solicitud de registro con gateway_identity, X_w_pub_key

        # Generar los valores de las claves públicas como bytes
        X_w_pub_key_xValue = X_w_pub_key.x
        X_w_pub_key_yValue = X_w_pub_key.y
        X_w_pub_key_dict = {"x": X_w_pub_key_xValue, "y": X_w_pub_key_yValue}

        second_payload = {
            "operation": "register_gateway",
            "Gateway_Identity": gateway_identity,
            "X_w_pub_key": X_w_pub_key_dict,
        }
        logger.info(f"[REG] Enviada información de registro al CA {second_payload}.")

        # Paso 3: Recibir sigma_a, Y_a_pub_key, h_a
        second_response = send_and_receive_persistent_socket(second_payload)
        logger.info("[REG] Respuesta recibida del CA.")
        if not second_response:
            logger.error("[REG] No se recibieron los parámetros del CA.")
            return
        sigma_w = second_response.get("sigma_w")
        Y_w_pub_key_dict = second_response.get("Y_w_pub_key")
        h_w = second_response.get("h_w")
        if sigma_w is None or Y_w_pub_key_dict is None or h_w is None:
            raise KeyError("[REG] Faltan parámetros en la respuesta del CA.")
        logger.info("[REG] Parámetros recibidos del CA.")

        # Guardar los parámetros de registro
        registration_parameters = {
            # Llave privada parcial del Gateway
            "x_w_priv_key": x_w_priv_key,
            # Llave pública parcial del Gateway
            "X_w_pub_key": X_w_pub_key,
            # Llave pública parcial generada por el CA
            "Y_w_pub_key": Y_w_pub_key_dict,
            # Llave de firma del Gateway
            "sigma_w": sigma_w,
            "h_w": h_w,
        }
        logger.info(
            f"[REG] Registro completado exitosamente con los siguientes parámetros: {registration_parameters}"
        )
    except socket.error as e:
        logger.error(f"[REG] Error de comunicación con el CA: {e}")
    except ValueError as e:
        logger.error(f"[REG] Error en la respuesta del CA: {e}")
    except Exception as e:
        logger.error(f"[REG] Error inesperado: {e}")
    finally:
        close_socket()


#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################


def handle_mutual_authentication(client_socket, hello_message):
    """
    Maneja la conexión de un cliente (IoT Device) y ejecuta el protocolo de autenticación mutua sin el CA.
    """
    global registration_parameters, gateway_identity
    try:

        # Paso 1: Recibir mensaje "hello" del dispositivo IoT
        if hello_message.get("step") != "hello":
            raise ValueError("Paso incorrecto recibido del dispositivo.")
        logger.info(f"[AUTH] Mensaje recibido del IoT Device: {hello_message}")

        # Paso 2: Enviar el token al dispositivo IoT: W, ID_w, X_w_pub_key, Y_w_pub_key, sigmaZ
        generated_data = generating_gateway_auth_token(hello_message)

        X_w_pub_key = registration_parameters.get("X_w_pub_key")
        X_w_pub_key_xValue = X_w_pub_key.x
        X_w_pub_key_yValue = X_w_pub_key.y
        X_w_pub_key_dict = {"x": X_w_pub_key_xValue, "y": X_w_pub_key_yValue}

        Y_w_pub_key_dict = registration_parameters.get("Y_w_pub_key")

        gateway_auth_token = {
            "operation": "mutual_authentication",
            "W": generated_data[0],
            "ID_w": gateway_identity,
            "X_w_pub_key": X_w_pub_key_dict,
            "Y_w_pub_key": Y_w_pub_key_dict,
            "sigma_z": generated_data[1],
        }
        client_socket.sendall(json.dumps(gateway_auth_token).encode("utf-8"))
        logger.info(
            f"[AUTH] Enviado token de autenticación al dispositivo IoT: {gateway_auth_token}"
        )

        # Step 3: Recibir el mensaje de autenticación del IoT: P_1, P_2, P_3, sigma_t, T_1, T_2, s_1, s_2
        iot_auth_token = json.loads(client_socket.recv(4096).decode("utf-8"))

        if not all(
            key in iot_auth_token
            for key in ["P_1", "P_2", "P_3", "sigma_t", "T_1", "T_2", "s_1", "s_2"]
        ):
            raise KeyError(
                "[AUTH] Faltan argumentos en la respuesta del dispositivo IoT."
            )
        logger.info(
            f"[AUTH] Puntos, compromisos y respuestas ZKP del dispositivo recibidos."
        )
        # Realizar los cálculos de verificación sobre el token de autenticación del dispositivo
        W_dict = generated_data[0]
        rng_5 = generated_data[2]
        IoT_Authentication(iot_auth_token, hello_message, W_dict, rng_5)

        # Enviar respuesta al dispositivo IoT
        response = {"operation": "mutual_authentication", "status": "success"}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
        logger.info(f"[AUTH] Autenticación mutua culminada.")

    except KeyError as e:
        logger.error(f"Error de clave faltante en los datos recibidos: {e}")
    except Exception as e:
        logger.error(f"Error inesperado durante la autenticación mutua: {e}")
    finally:
        client_socket.close()
        close_socket()


def generating_gateway_auth_token(hello_data):
    global registration_parameters

    # Inicializar la llave recibida
    A_dict = hello_data.get("one_time_public_key")

    # Generar el nonce r_5
    rng_5 = int.from_bytes(os.urandom(8), "big") % P256.q

    X_w_pub_key = registration_parameters.get("X_w_pub_key")

    W = rng_5 * X_w_pub_key
    W_xValue = W.x
    W_yValue = W.y
    W_dict = {"x": W_xValue, "y": W_yValue}

    # Función Hash
    A_xValue = A_dict.get("x")
    A_yValue = A_dict.get("y")

    I_g = Hash_MAPFS([A_xValue, A_yValue, W_xValue, W_yValue])

    sigma_w = registration_parameters.get("sigma_w")
    x_w_priv_key = registration_parameters.get("x_w_priv_key")

    sigma_z = (I_g * sigma_w + rng_5 * x_w_priv_key) % P256.q

    return W_dict, sigma_z, rng_5


def IoT_Authentication(iot_auth_token, hello_data, W_dict, rng_5):
    global registration_parameters, P_IoT_key_xValue, P_IoT_key_yValue

    # Inicializar las variables recibidas
    P_1_dict = iot_auth_token.get("P_1")
    P_1 = Point(P_1_dict.get("x"), P_1_dict.get("y"), curve=P256)

    P_2_dict = iot_auth_token.get("P_2")
    P_2 = Point(P_2_dict.get("x"), P_2_dict.get("y"), curve=P256)

    P_3_dict = iot_auth_token.get("P_3")
    P_3 = Point(P_3_dict.get("x"), P_3_dict.get("y"), curve=P256)

    sigma_t = iot_auth_token.get("sigma_t")

    T_1_dict = iot_auth_token.get("T_1")
    T_1 = Point(T_1_dict.get("x"), T_1_dict.get("y"), curve=P256)

    T_2_dict = iot_auth_token.get("T_2")
    T_2 = Point(T_2_dict.get("x"), T_2_dict.get("y"), curve=P256)

    s_1 = iot_auth_token.get("s_1")
    s_2 = iot_auth_token.get("s_2")

    A_dict = hello_data.get("one_time_public_key")
    A = Point(A_dict.get("x"), A_dict.get("y"), curve=P256)

    # Cómputo de I_a
    I_a = Hash_MAPFS(
        [A_dict.get("x"),
        A_dict.get("y"),
        P_1_dict.get("x"),
        P_1_dict.get("y"),
        P_2_dict.get("x"),
        P_2_dict.get("y"),
        P_3_dict.get("x"),
        P_3_dict.get("y"),
        T_1_dict.get("x"),
        T_1_dict.get("y"),
        T_2_dict.get("x"),
        T_2_dict.get("y"),
        W_dict.get("x"),
        W_dict.get("y"),]
    )
    logger.info(
        "[AUTH] Verificando la firma del IoT."
    )
    assert sigma_t * P256.G == (
        I_a * P_1 + I_a * P_2 + I_a * P_3 + A
    ), "Error autenticando el dispositivo IoT."

    # Verificar las respuesta ZKP
    P_IoT_key = Point(P_IoT_key_xValue, P_IoT_key_yValue, curve=P256)

    assert s_1 * P_IoT_key == (
        I_a * P_2 + T_1
    ), "Error verificando la llave pública del CA.."
    assert s_2 * P_1 == (I_a * P_3 + T_2), "Error verificando I_1"

    logger.info(
        "[AUTH] Llave pública del CA y I_1 verificados."
    )
    # Función de hash H_0(r_5x_wA)
    x_w_priv_key = registration_parameters.get("x_w_priv_key")
    A_xValue = (rng_5 * x_w_priv_key * A).x
    A_yValue = (rng_5 * x_w_priv_key * A).y

    K_s_int = Hash_MAPFS([A_xValue, A_yValue])
    K_s_int = int(str(K_s_int)[:16])
    logger.info(f"[AUTH] La llave de sesión en el gateway es: {K_s_int}")
    K_s_bytes = K_s_int.to_bytes(AES.block_size, "big")
    session_keys[hello_data.get("h_a")] = K_s_bytes

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
                encoded_message[key] = base64.b64encode(value).decode(
                    "utf-8"
                )  # Convertir bytes a base64 y luego a str
            else:
                encoded_message[key] = value
        # logger.info(f"send_and_receive_persistent_socket- encoded_message={encoded_message}"#)
        cloud_socket.sendall(
            json.dumps(encoded_message).encode("utf-8")
        )  # Enviar mensaje

        response = cloud_socket.recv(4096)  # Recibir respuesta
        received_message_dict = json.loads(response.decode("utf-8"))
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
        # logger.info(f"send_and_receive_persistent_socket- decoded_response={decoded_message}")
        return decoded_message
    except socket.error as e:
        logger.error(f"Error en la comunicación por socket persistente: {e}")
        cloud_socket = None  # Marcar el socket como no válido
        raise e


#######################################################
#                 INTERCAMBIAR MENSAJES               #
#######################################################


def handle_send_metrics(client_socket, message):
    """
    Manejar el mensaje 'send_metrics' enviado por el dispositivo IoT.

    Args:
        client_socket: El socket del cliente IoT.
        message (dict): Mensaje recibido del dispositivo IoT.
    """
    try:
        # Extraer los campos necesarios del mensaje
        ID_obfuscated = message.get("h_a")
        iv_base64 = message.get("iv")
        encrypted_metrics_base64 = message.get("encrypted_metrics")

        if not ID_obfuscated or not iv_base64 or not encrypted_metrics_base64:
            raise ValueError(
                "Faltan campos en el mensaje recibido ('h_a', 'iv' o 'encrypted_metrics')."
            )

        # Buscar la llave de sesión correspondiente
        K_s_bytes = session_keys.get(ID_obfuscated)
        if not K_s_bytes:
            raise ValueError(
                f"No se encontró una llave de sesión para h_a={ID_obfuscated}."
            )

        # Decodificar IV y las métricas cifradas desde Base64
        iv = base64.b64decode(iv_base64)
        encrypted_metrics = base64.b64decode(encrypted_metrics_base64)

        # Crear el descifrador AES en modo CBC
        cipher = AES.new(K_s_bytes, AES.MODE_CBC, iv)

        # Descifrar y deshacer el padding de las métricas
        decrypted_metrics_json = unpad(
            cipher.decrypt(encrypted_metrics), AES.block_size
        )

        # Convertir las métricas descifradas de JSON a diccionario
        metrics = json.loads(decrypted_metrics_json.decode("utf-8"))
        logger.info(f"[METRICS] Métricas recibidas descifradas: {metrics}")

        # Enviar respuesta al dispositivo IoT
        response = {"status": "success", "message": "Métricas recibidas correctamente."}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
        logger.info("[METRICS] Respuesta enviada al dispositivo IoT.")

    except (ValueError, KeyError) as e:
        logger.error(f"[METRICS] Error en el mensaje recibido: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"[METRICS] Error inesperado durante el manejo de métricas: {e}")
        response = {"status": "error", "message": "Error inesperado."}
        client_socket.sendall(json.dumps(response).encode("utf-8"))

if __name__ == "__main__":
    time.sleep(10)
    # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8010.")
    start_http_server(8010)
    
    # Realiza el registro ante el CA
    gateway_registration()
    
    # Inicia el socket
    start_gateway_socket()
