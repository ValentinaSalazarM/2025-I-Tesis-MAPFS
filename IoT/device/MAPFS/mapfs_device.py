from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter, Histogram

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/MAPFS-device.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Device")

# Configuración del socket
GATEWAY_HOST = "mapfs-gateway"  # Dirección IP del Gateway
GATEWAY_PORT = 5000  # Puerto del Gateway

CA_HOST = "mapfs-cloud"  # Dirección de la CA
CA_PORT = 5001  # Puerto de la CA

gateway_socket = None

# Parámetros publicados por el CA
Pub_gc_key_xValue = None
Pub_gc_key_yValue = None

P_IoT_key_xValue = None
P_IoT_key_yValue = None

# Parámetros de registro
registration_parameters = {}
iot_identity = int.from_bytes(os.urandom(8), "big")

# Llaves de sesión con Gateways
K_s_bytes = None


#######################################################
#              REGISTRO DISPOSITIVO IOT               #
#######################################################


def IoT_registration():
    """
    Registro del dispositivo IoT utilizando comunicación por sockets.
    """
    global registration_parameters, iot_identity, Pub_gc_key_xValue, Pub_gc_key_yValue, P_IoT_key_xValue, P_IoT_key_yValue

    try:
        # Configuración del socket para comunicarse con el CA
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((CA_HOST, CA_PORT))
            logger.info(f"[REG] Conectado al CA en {CA_HOST}:{CA_PORT}")

            # Paso 1: Enviar al CA la solicitud de registro
            first_payload = {"operation": "register_device"}
            sock.sendall(json.dumps(first_payload).encode("utf-8"))
            logger.info("[REG] Enviada solicitud de registro al CA.")

            # Recibir parámetros públicos del CA
            first_response = sock.recv(4096)
            first_message = json.loads(first_response.decode("utf-8"))

            Pub_gc_key = first_message.get("Pub_gc_key")
            Pub_gc_key_xValue = Pub_gc_key.get("x")
            Pub_gc_key_yValue = Pub_gc_key.get("y")

            P_IoT_key = first_message.get("P_IoT_key")
            P_IoT_key_xValue = P_IoT_key.get("x")
            P_IoT_key_yValue = P_IoT_key.get("y")

            logger.info(f"[REG] Recibidos parámetros públicos del CA: {first_message}.")

            # Paso 2: Generación de las llaves del IoT y de su identidad
            x_a_priv_key, X_a_pub_key = keys.gen_keypair(P256)

            # Obtener un punto aleatorio en P256 (llave pública, la privada no se almacena)
            _, h_x = keys.gen_keypair(P256)

            # Paso 3: Enviar al CA la solicitud de registro con IoT_Identity, X_a_pub_key, h_x

            # Generar los valores de las claves públicas como bytes
            X_a_pub_key_xValue = X_a_pub_key.x
            X_a_pub_key_yValue = X_a_pub_key.y
            X_a_pub_key_dict = {"x": X_a_pub_key_xValue, "y": X_a_pub_key_yValue}

            h_x_pub_key_xValue = h_x.x
            h_x_pub_key_yValue = h_x.y
            h_x_pub_key_dict = {"x": h_x_pub_key_xValue, "y": h_x_pub_key_yValue}

            second_payload = {
                "operation": "register_device",
                "IoT_Identity": iot_identity,
                "X_a_pub_key": X_a_pub_key_dict,
                "h_x": h_x_pub_key_dict,
            }
            sock.sendall(json.dumps(second_payload).encode("utf-8"))
            logger.info(
                f"[REG] Enviada información de registro al CA {second_payload}."
            )

            # Paso 4: Recibir sigma_a, Y_a_pub_key, h_a
            second_response = sock.recv(4096)
            if not second_response:
                logger.error("[REG] No se recibieron los parámetros del CA.")
                return
            second_message = json.loads(second_response.decode("utf-8"))
            sigma_a = second_message.get("sigma_a")
            Y_a_pub_key_dict = second_message.get("Y_a_pub_key")
            h_a = second_message.get("h_a")
            if sigma_a is None or Y_a_pub_key_dict is None or h_a is None:
                raise KeyError("[REG] Faltan parámetros en la respuesta del CA.")
            logger.info(f"[REG] Parámetros recibidos del CA: {second_message}.")

            # Guardar los parámetros de registro
            registration_parameters = {
                # Llave privada parcial del IoT
                "x_a_priv_key": x_a_priv_key,
                # Llave pública parcial del IoT
                "X_a_pub_key": X_a_pub_key,
                # Llave pública parcial generada por el CA
                "Y_a_pub_key": Y_a_pub_key_dict,
                # Llave de firma del IoT
                "sigma_a": sigma_a,
                "h_a": h_a,
            }
            logger.info(
                f"[REG] Registro completado exitosamente con los siguientes parámetros: {registration_parameters}"
            )
    except KeyError as e:
        logger.error(f"[REG] Clave faltante: {e}")
    except socket.error as e:
        logger.error(f"[REG] Error en la comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"[REG] Error inesperado durante el registro: {e}")


#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################


def mutual_authentication():
    """
    Protocolo de autenticación mutua para el dispositivo IoT.
    Este proceso asegura la autenticidad y sincronización de claves entre el dispositivo IoT y el gateway.
    """

    global registration_parameters

    try:

        # Inicializar el socket persistente con el Gateway
        initialize_socket()

        # Paso 1: Enviar mensaje inicial ("hello") al Gateway
        rng_1 = int.from_bytes(os.urandom(8), "big") % P256.q
        rng_2 = int.from_bytes(os.urandom(8), "big") % P256.q
        rng_3 = int.from_bytes(os.urandom(8), "big") % P256.q
        rng_4 = int.from_bytes(os.urandom(8), "big") % P256.q
        random_nonces = [rng_1, rng_2, rng_3, rng_4]

        # Generar IoT one-time public key
        X_a_pub_key = registration_parameters.get("X_a_pub_key")

        A = rng_1 * X_a_pub_key
        A_dict = {"x": A.x, "y": A.y}

        first_request = {
            "operation": "mutual_authentication",
            "h_a": registration_parameters.get("h_a"),
            "step": "hello",
            "one_time_public_key": A_dict,
        }
        first_response = send_and_receive_persistent_socket(first_request)
        logger.info(f"[AUTH] Mensaje 'hello' enviado al Gateway {first_request}.")

        # Paso 2: Procesar el token de autenticación del gateway (W, ID_w, X_w_pub_key, Y_w_pub_key, sigma_z)
        if not all(
            key in first_response
            for key in ["W", "ID_w", "X_w_pub_key", "Y_w_pub_key", "sigma_z"]
        ):
            raise KeyError(
                "[AUTH] Faltan argumentos en la respuesta del dispositivo IoT."
            )
        logger.info(
            f"[AUTH] Token de autenticación del Gateway recibido: {first_response}"
        )
        generated_data = gateway_auth_on_IoT_side(first_response, random_nonces, A)
        second_request = {
            "operation": "mutual_authentication",
            "P_1": generated_data[0],
            "P_2": generated_data[1],
            "P_3": generated_data[2],
            "sigma_t": generated_data[3],
            "T_1": generated_data[4],
            "T_2": generated_data[5],
            "s_1": generated_data[6],
            "s_2": generated_data[7],
        }
        # Paso 3: Enviar P_1_dict, P_2_dict, P_3_dict, sigma_t, T_1_dict, T_2_dict, s_1, s_2
        logger.info(
            f"[AUTH] Puntos, compromisos y respuestas ZKP enviadas al gateway: {second_request}"
        )
        second_response = send_and_receive_persistent_socket(second_request)
        if second_response.get("status") == "success":
            logger.info("[AUTH] Autenticación mutua culminada.")
    except KeyError as e:
        logger.error(f"[AUTH] Error de datos faltantes en la respuesta: {e}")
    except socket.error as e:
        logger.error(f"[AUTH] Error en la comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"[AUTH] Error inesperado: {e}")
        close_socket()


def gateway_auth_on_IoT_side(gateway_auth_token, random_nonces, A):
    global registration_parameters, Pub_gc_key_xValue, Pub_gc_key_yValue, P_IoT_key_xValue, P_IoT_key_yValue, K_s_bytes

    # Inicializar las variables recibidas
    ID_w = gateway_auth_token.get("ID_w")

    W_dict = gateway_auth_token.get("W")
    W = Point(W_dict.get("x"), W_dict.get("y"), curve=P256)
        
    Y_w_pub_key_dict = gateway_auth_token.get("Y_w_pub_key")
    Y_w_pub_key = Point(
        Y_w_pub_key_dict.get("x"), Y_w_pub_key_dict.get("y"), curve=P256
    )
    sigma_z = gateway_auth_token.get("sigma_z")

    # Cómputo de I_g
    I_g = Hash_MAPFS([A.x, A.y, W_dict.get("x"), W_dict.get("y")])

    # Cómputo de H_1
    X_w_pub_key_dict = gateway_auth_token.get("X_w_pub_key")
    h_w = Hash_MAPFS(
        [
        X_w_pub_key_dict.get("x"),
        X_w_pub_key_dict.get("y"),
        Pub_gc_key_xValue,
        Pub_gc_key_yValue,
        Y_w_pub_key_dict.get("x"),
        Y_w_pub_key_dict.get("y"),]
    )

    # Verificar la firma del Gateway
    Pub_gc_key = Point(Pub_gc_key_xValue, Pub_gc_key_yValue, curve=P256)
    P_IoT_key = Point(P_IoT_key_xValue, P_IoT_key_yValue, curve=P256)
   
    assert sigma_z*P256.G == (I_g * Pub_gc_key + I_g * h_w * Y_w_pub_key + W), "Error en la autenticación de la firma del Gateway."

    logger.info("[AUTH] Autenticación de la firma del Gateway exitosa.")

    # Cómputo de H_0
    rng_1 = random_nonces[0]
    x_a_priv_key = registration_parameters.get("x_a_priv_key")

    A_xValue = (rng_1 * x_a_priv_key * W).x
    A_yValue = (rng_1 * x_a_priv_key * W).y

    K_s_int = Hash_MAPFS([A_xValue, A_yValue])
    K_s_int = int(str(K_s_int)[:16])
    K_s_bytes = K_s_int.to_bytes(AES.block_size, "big")
    logger.info(f"[AUTH] La llave de sesión en el dispositivo IoT es: {K_s_int}")

    rng_2 = random_nonces[1]
    rng_3 = random_nonces[2]
    rng_4 = random_nonces[3]

    Y_a_pub_key_dict = registration_parameters.get("Y_a_pub_key")
    Y_a_pub_key = Point(
        Y_a_pub_key_dict.get("x"), Y_a_pub_key_dict.get("y"), curve=P256
    )

    h_a = registration_parameters.get("h_a")

    # Cómputo del punto base
    P_1 = rng_2 * Y_a_pub_key
    P_1_xValue = P_1.x
    P_1_yValue = P_1.y
    P_1_dict = {"x": P_1_xValue, "y": P_1_yValue}

    P_2 = rng_2 * P_IoT_key
    P_2_xValue = P_2.x
    P_2_yValue = P_2.y
    P_2_dict = {"x": P_2_xValue, "y": P_2_yValue}

    # Cómputo de puntos aleatorios
    P_3 = rng_2 * h_a * Y_a_pub_key
    P_3_xValue = P_3.x
    P_3_yValue = P_3.y
    P_3_dict = {"x": P_3_xValue, "y": P_3_yValue}

    # Compromisos ZKP para probar
    T_1 = rng_3 * P_IoT_key
    T_1_xValue = T_1.x
    T_1_yValue = T_1.y
    T_1_dict = {"x": T_1_xValue, "y": T_1_yValue}

    T_2 = rng_4 * P_1
    T_2_xValue = T_2.x
    T_2_yValue = T_2.y
    T_2_dict = {"x": T_2_xValue, "y": T_2_yValue}

    # Función de hash H_4(A,P_1,P_2,P_3,T_1,T_2,W)
    I_a = Hash_MAPFS(
        [A.x,
        A.y,
        P_1_xValue,
        P_1_yValue,
        P_2_xValue,
        P_2_yValue,
        P_3_xValue,
        P_3_yValue,
        T_1_xValue,
        T_1_yValue,
        T_2_xValue,
        T_2_yValue,
        W_dict.get("x"),
        W_dict.get("y"),]
    )

    sigma_a = registration_parameters.get("sigma_a")

    # Cómputo de la firma aleatoria que será verificada por el Gateway
    sigma_t = (I_a * rng_2 * sigma_a + rng_1 * x_a_priv_key) % P256.q
    logger.info(f"[AUTH] Cómputo de la firma del dispositivo IoT completada.") 

    # cómputo de las respuestas de ZKP
    s_1 = (rng_2 * I_a + rng_3) % P256.q
    s_2 = (h_a * I_a + rng_4) % P256.q

    return P_1_dict, P_2_dict, P_3_dict, sigma_t, T_1_dict, T_2_dict, s_1, s_2


#######################################################
#                 INTERCAMBIAR MENSAJES               #
#######################################################


def message_authetication():
    """
    Envía métricas cifradas al Gateway utilizando AES en modo CBC.

    """
    try:
        while True:
            sensor_data = {
                "temperature": random.uniform(20.0, 30.0),
                "humidity": random.uniform(50, 70),
            }

            # Serializar las métricas a JSON
            metrics_json = json.dumps(sensor_data).encode("utf-8")

            # Generar un IV aleatorio para CBC
            iv = Random.new().read(AES.block_size)

            # Crear el cifrador AES en modo CBC
            cipher = AES.new(K_s_bytes, AES.MODE_CBC, iv)

            # Cifrar las métricas con padding
            encrypted_metrics = cipher.encrypt(pad(metrics_json, AES.block_size))

            # Construir el mensaje para enviar al Gateway
            payload = {
                "operation": "send_metrics",
                "h_a": registration_parameters.get("h_a"),
                "iv": base64.b64encode(iv).decode("utf-8"),
                "encrypted_metrics": base64.b64encode(encrypted_metrics).decode(
                    "utf-8"
                ),
            }

            # Enviar el mensaje al Gateway mediante sockets
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((GATEWAY_HOST, GATEWAY_PORT))
                sock.sendall(json.dumps(payload).encode("utf-8"))
                logger.info("[METRICS] Mensaje cifrado enviado al Gateway.")

                # Recibir respuesta del Gateway
                response = sock.recv(4096)
                if response:
                    response_message = json.loads(response.decode("utf-8"))
                    logger.info(
                        f"[METRICS] Respuesta recibida del Gateway: {response_message}"
                    )
            time.sleep(60)
    except ValueError as e:
        logger.error(f"[METRICS] Error de validación: {e}")
    except socket.error as e:
        logger.error(f"[METRICS] Error de comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"[METRICS] Error inesperado: {e}")


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
                encoded_message[key] = base64.b64encode(value).decode(
                    "utf-8"
                )  # Convertir bytes a base64 y luego a str
            else:
                encoded_message[key] = value
        # logger.info(f"send_and_receive_persistent_socket- encoded_message={encoded_message}")
        gateway_socket.sendall(
            json.dumps(encoded_message).encode("utf-8")
        )  # Enviar mensaje

        response = gateway_socket.recv(4096)  # Recibir respuesta
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
        gateway_socket = None  # Marcar el socket como no válido
        raise e

if __name__ == "__main__":
    time.sleep(15)
     # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8012.")
    start_http_server(8012)
    # Realiza el registro y la autenticación mutua
    IoT_registration()
    # Simula el envío de métricas al Gateway
    mutual_authentication()
    #message_authetication()

