import socket
import json
import logging
import time
import os

from locust import User, task, between, events
from fastecdsa import keys
from fastecdsa.curve import P256

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
            step_start = time.time()
            _, random_pub_key = keys.gen_keypair(P256)
            value = {"x": random_pub_key.x, "y": random_pub_key.y}
            hello_message = {
                "operation": "mutual_authentication",
                "step": "hello",
                "one_time_public_key": value,
            }
            self.client.send(hello_message)

            # Paso 2: Recibir token de autenticación del gateway
            gateway_token = self.client.receive()
            events.request.fire(
                request_type="socket",
                name="mutual_auth/hello",
                response_time=(time.time() - step_start)*1000,
                response_length=len(str(gateway_token)),
                exception=None,
            )
            logger.info("Token recibido: %s", gateway_token)

            # Paso 3: Enviar mensaje de autenticación del IoT
            step_start = time.time()
            iot_auth_token = {
                "P_1": value,
                "P_2": value,
                "P_3": value,
                "sigma_t": int.from_bytes(os.urandom(8), "big"),
                "T_1": value,
                "T_2": value,
                "s_1": int.from_bytes(os.urandom(8), "big"),
                "s_2": int.from_bytes(os.urandom(8), "big"),
            }
            self.client.send(iot_auth_token)

            # Paso 4: Recibir respuesta final del gateway
            response = self.client.receive()
            events.request.fire(
                request_type="socket",
                name="mutual_auth/iot_auth",
                response_time=(time.time() - step_start)*1000,
                response_length=len(str(response)),
                exception=None,
            )
            logger.info("Respuesta final: %s", response)
            
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
