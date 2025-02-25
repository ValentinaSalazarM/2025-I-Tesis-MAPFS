from common.cripto_primitivas import *
import threading

# Métricas
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="MAPFS time=%(asctime)s level=%(levelname)s msg=\'%(message)s\'",
    handlers=[logging.FileHandler("/logs/MAPFS-gateway.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Gateway")

# Configuración de los servidores socket de comunicación
HOST = "0.0.0.0"
PORT = 5000
REVOCATION_PORT = 6000

# Configuración del servidor socket de comunicación para registro con el Cloud
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

# Dispositivos IoT autenticados
authenticated_devices = {}

# Estructura para almacenar los dispositivos revocados
revoked_devices = {}


#######################################################
#               SERVIDOR SOCKET GATEWAY               #
#######################################################


def start_gateway_socket():
    """
    Inicia el servidor socket para manejar conexiones del IoT Device.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
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
        logger.info(f"[REG] Enviada información de registro al CA: {second_payload}.")

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
            f"[REG] Registro completado exitosamente con los siguientes parámetros."
        )
    except socket.error as e:
        logger.error(f"[REG] Error de comunicación con el CA: {e}")
    except ValueError as e:
        logger.error(f"[REG] Error en la respuesta del CA: {e}")
    except Exception as e:
        logger.error(f"[REG] Error inesperado: {e}")
    finally:
        close_socket()
        logger.info("[REG] Conexión con el CA cerrada.")


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
            raise KeyError("Paso incorrecto recibido del dispositivo.")
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
        logger.error(f"[AUTH] Clave faltante en los datos recibidos: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"[AUTH] Error durante la autenticación mutua: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    finally:
        client_socket.close()
        close_socket()
        logger.info("[AUTH] Conexión con el CA cerrada.")


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
    global registration_parameters, P_IoT_key_xValue, P_IoT_key_yValue, authenticated_devices

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
        [
            A_dict.get("x"),
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
            W_dict.get("y"),
        ]
    )
    logger.info("[AUTH] Verificando la firma del IoT.")
    assert sigma_t * P256.G == (
        I_a * P_1 + I_a * P_2 + I_a * P_3 + A
    ), "Error autenticando el dispositivo IoT."

    # Verificar las respuesta ZKP
    P_IoT_key = Point(P_IoT_key_xValue, P_IoT_key_yValue, curve=P256)

    assert s_1 * P_IoT_key == (
        I_a * P_2 + T_1
    ), "Error verificando la llave pública del CA.."
    assert s_2 * P_1 == (I_a * P_3 + T_2), "Error verificando I_1"

    logger.info("[AUTH] Llave pública del CA y I_1 verificados.")
    # Función de hash H_0(r_5x_wA)
    x_w_priv_key = registration_parameters.get("x_w_priv_key")
    A_xValue = (rng_5 * x_w_priv_key * A).x
    A_yValue = (rng_5 * x_w_priv_key * A).y

    K_s_int = Hash_MAPFS([A_xValue, A_yValue])
    K_s_int = int(str(K_s_int)[:16])
    logger.info(f"[AUTH] La llave de sesión en el gateway es: {K_s_int}")
    K_s_bytes = K_s_int.to_bytes(AES.block_size, "big")

    # Hash derivado de las claves públicas efímeras del IoT y el Gateway para identificar la sesión autenticada
    unique_identifier = Hash_MAPFS(
        [A_dict.get("x"), A_dict.get("y"), W_dict.get("x"), W_dict.get("y")]
    )
    authenticated_devices[unique_identifier] = {
        "session_key": K_s_bytes,
        "P_1": P_1_dict,
        "P_3": P_3_dict,
    }
    logger.info(f"[AUTH] unique_identifier: {unique_identifier}")


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
        # Extraer parámetros de autenticación
        A_dict = message.get("A")
        W_dict = message.get("W")

        if not A_dict or not W_dict:
            raise ValueError(
                "Faltan claves públicas en el mensaje recibido ('A', 'W')."
            )

        # Generar el identificador único del dispositivo
        authentication_id = Hash_MAPFS(
            [A_dict.get("x"), A_dict.get("y"), W_dict.get("x"), W_dict.get("y")]
        )

        # Verificar si el dispositivo está autenticado
        authentication_parameters = authenticated_devices.get(authentication_id)

        # Verificar si el dispositivo está revocado
        if authentication_parameters:
            P_1_dict = authentication_parameters.get("P_1")
            P_3_dict = authentication_parameters.get("P_3")

            if not P_1_dict or not P_3_dict:
                raise ValueError(f"Faltan parámetros P_1 y P_3 para verificar revocación.")

            if is_device_revoked(P_1_dict, P_3_dict):
                logger.warning(
                    f"[METRICS] Dispositivo revocado intentó enviar métricas. Bloqueando acceso."
                )
                response = {
                    "status": "failed",
                    "message": "Dispositivo revocado. No se aceptan métricas.",
                }
                client_socket.sendall(json.dumps(response).encode("utf-8"))
                raise ValueError("Dispositivo revocado.")
        else:
            response = {
                "status": "failed",
                "message": "Dispositivo no autenticado. No se aceptan métricas.",
            }
            client_socket.sendall(json.dumps(response).encode("utf-8"))
            raise ValueError(f"Dispositivo con ID: {authentication_id} no autenticado.")

        # Extraer métricas cifradas
        iv_base64 = message.get("iv")
        encrypted_metrics_base64 = message.get("encrypted_metrics")

        if not iv_base64 or not encrypted_metrics_base64:
            raise ValueError(
                "Faltan campos en el mensaje recibido ('iv', 'encrypted_metrics')."
            )

        # Obtener la clave de sesión del dispositivo
        K_s_bytes = authentication_parameters.get("session_key")
        if not K_s_bytes:
            raise ValueError(
                f"No se encontró una llave de sesión para {authentication_id}."
            )

        # Decodificar IV y métricas cifradas desde Base64
        iv = base64.b64decode(iv_base64)
        encrypted_metrics = base64.b64decode(encrypted_metrics_base64)

        # Descifrar y deshacer el padding de las métricas
        cipher = AES.new(K_s_bytes, AES.MODE_CBC, iv)
        decrypted_metrics_json = unpad(
            cipher.decrypt(encrypted_metrics), AES.block_size
        )

        # Convertir las métricas descifradas de JSON a diccionario
        metrics = json.loads(decrypted_metrics_json.decode("utf-8"))
        logger.info(f"[METRICS] Métricas recibidas descifradas: {metrics}")

        # Enviar respuesta de éxito al dispositivo IoT
        response = {
            "status": "success",
            "message": "Métricas recibidas correctamente.",
        }
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


def is_device_revoked(P_1_dict, P_3_dict):
    """
    Verifica si un dispositivo IoT está en la lista de revocados.
    """
    revocation_id = Hash_MAPFS(
        [P_1_dict.get("x"), P_1_dict.get("y"), P_3_dict.get("x"), P_3_dict.get("y")]
    )
    return revocation_id in revoked_devices


#######################################################
#                 REVOCAR IDENTIDADES                 #
#######################################################


def report_misbehaving_device():
    """
    Evalúa periódicamente si un dispositivo IoT autenticado se comporta de manera maliciosa
    y lo reporta al Cloud con los parámetros P1 y P3.
    """
    global authenticated_devices
    logger.info(f"Monitoreando actividad sospechosa de los dispositivos")
    while True:
        for unique_identifier, session_data in authenticated_devices.items():
            authenticated = len(authenticated_devices)
            logger.info(f"Conteo: {authenticated}")

            # Detección de anomalías
            if detect_suspicious_activity(unique_identifier):
                logger.warning(
                    f"[REVOC] Actividad sospechosa detectada para {unique_identifier}. Solicitando revocación."
                )

                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        logger.info(
                            f"[REVOC] Enviando solicitud de revocación a {CA_HOST}:{CA_PORT}."
                        )
                        s.connect((CA_HOST, CA_PORT))

                        # Enviar solicitud al Cloud
                        P1 = session_data.get("P_1")
                        P3 = session_data.get("P_3")
                        payload = {
                            "operation": "identify_and_revoke",
                            "P_1": P1,
                            "P_3": P3,
                        }
                        s.sendall(json.dumps(payload).encode())
                        
                        response = s.recv(4096)
                        last_response = json.loads(response.decode())
                        if last_response.get("status") == "failed" or last_response.get("status") == "error":
                            logger.error("Las métricas no han sido procesadas exitosamente.")

                except Exception as e:
                    logger.error(f"[REVOC] Error al contactar con el Cloud: {e}")
        time.sleep(400)  


def listen_for_revocation():
    """
    Servidor socket exclusivo para recibir órdenes de revocación del Cloud.
    """
    global revoked_devices
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, REVOCATION_PORT))
        server_socket.listen()
        logger.info(
            f"[REVOC] Esperando respuestas de revocación en el puerto {REVOCATION_PORT}."
        )

        while True:
            try:
                client_socket, addr = server_socket.accept()
                with client_socket:
                    response = json.loads(client_socket.recv(4096).decode())

                    if "ID_a" not in response:
                        logger.error(
                            "[REVOC] Respuesta inválida del Cloud: Falta ID_a."
                        )
                        return

                    logger.info(f"[REVOC] Mensaje recibido: {response}")
                    P_1_dict = response.get("P_1")
                    P_3_dict = response.get("P_3")

                    if not P_1_dict or not P_3_dict:
                        logger.error("[REVOC] Respuesta inválida del Cloud.")
                        return

                    # Registrar el dispositivo en la lista de revocados
                    revocation_id = Hash_MAPFS(
                        [
                            P_1_dict.get("x"),
                            P_1_dict.get("y"),
                            P_3_dict.get("x"),
                            P_3_dict.get("y"),
                        ]
                    )
                    revoked_devices[revocation_id] = response.get("ID_a")
                    logger.info(f"[REVOC] revocation_id = {revocation_id}")
                    found = False
                    for (
                        unique_identifier,
                        session_data,
                    ) in authenticated_devices.items():
                        logger.info(f"unique_identifier = {unique_identifier}")
                        if P_1_dict == session_data.get(
                            "P_1"
                        ) and P_3_dict == session_data.get("P_3"):
                            found = authenticated_devices.pop(
                                unique_identifier, None
                            )  # Elimina la clave y devuelve su valor
                            if found:
                                logger.info(
                                    f"[REVOC] Dispositivo revocado y bloqueado."
                                )
                            break
                    if not found:
                        logger.info(
                            f"[REVOC] El dispositivo ya ha sido revocado y bloqueado previamente."
                        )
            except Exception as e:
                logger.error(f"Error durante la revocación: {e}")


def detect_suspicious_activity(unique_identifier):
    """
    Lógica para detectar dispositivos IoT que se comportan de manera maliciosa.
    - Se podría ampliar con reglas de detección de tráfico anómalo, intentos fallidos, etc.
    """
    # Simulación: Cada 60 segundos, hay un 10% de probabilidad de marcar a un dispositivo como sospechoso
    suspicious = (time.time() + hash(unique_identifier)) % 60 < 6
    return suspicious


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


if __name__ == "__main__":
    time.sleep(10)
    os.makedirs("../../Logs/", mode=0o777, exist_ok=True)
    
    # Iniciar el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8010.")
    start_http_server(8010)

    # Realizar el registro ante el CA
    gateway_registration()

    # Iniciar el socket para autenticación y comunicación con IoT devices
    socket_thread = threading.Thread(target=start_gateway_socket, daemon=True)
    socket_thread.start()

    # Iniciar el servidor de revocación en un hilo separado
    revocation_thread = threading.Thread(target=listen_for_revocation, daemon=True)
    revocation_thread.start()

    # Iniciar el monitoreo de dispositivos maliciosos
    monitoring_thread = threading.Thread(target=report_misbehaving_device, daemon=True)
    monitoring_thread.start()

    # Mantener el programa en ejecución
    socket_thread.join()
    revocation_thread.join()
    monitoring_thread.join()
