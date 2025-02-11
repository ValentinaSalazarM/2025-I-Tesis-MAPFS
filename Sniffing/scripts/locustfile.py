import socket
import json
from locust import User, task, between, events
import logging

# Configuración del logger
logger = logging.getLogger("locust")

class SocketClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def send(self, message):
        self.socket.sendall(json.dumps(message).encode("utf-8"))

    def receive(self):
        data = self.socket.recv(4096)
        return json.loads(data.decode("utf-8"))

    def close(self):
        self.socket.close()

class SocketUser(User):
    wait_time = between(1, 5)
    host = "localhost"
    port = 5000

    def on_start(self):
        self.client = SocketClient(self.host, self.port)
        self.client.connect()

    @task
    def mutual_authentication(self):
        try:
            # Paso 1: Enviar mensaje "hello" al gateway
            hello_message = {
                "operation": "mutual_authentication",
                "step": "hello",
                "device_id": "device_123",
            }
            self.client.send(hello_message)

            # Paso 2: Recibir token de autenticación del gateway
            gateway_token = self.client.receive()
            logger.info("Token recibido: %s", gateway_token)

            # Paso 3: Enviar mensaje de autenticación del IoT
            iot_auth_token = {
                "P_1": "value1",
                "P_2": "value2",
                "P_3": "value3",
                "sigma_t": "value4",
                "T_1": "value5",
                "T_2": "value6",
                "s_1": "value7",
                "s_2": "value8",
            }
            self.client.send(iot_auth_token)

            # Paso 4: Recibir respuesta final del gateway
            response = self.client.receive()
            logger.info("Respuesta final: %s", response)

            # Registrar la solicitud como exitosa
            events.request.fire(
                request_type="socket",
                name="mutual_authentication",
                response_time=100,  # Tiempo de respuesta en ms (puedes calcularlo)
                response_length=len(str(response)),
                exception=None,
            )
        except Exception as e:
            # Registrar la solicitud como fallida
            logger.error("Error durante la autenticación: %s", e)
            events.request.fire(
                request_type="socket",
                name="mutual_authentication",
                response_time=0,
                response_length=0,
                exception=str(e),
            )

    def on_stop(self):
        self.client.close()