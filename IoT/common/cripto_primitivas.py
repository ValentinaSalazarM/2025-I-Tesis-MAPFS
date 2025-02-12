from fastecdsa import keys
from fastecdsa.curve import Curve, P256
from fastecdsa.point import Point
from Crypto import Random
from Crypto.Util.Padding import unpad, pad
from Crypto.Cipher import AES

from ecdsa import SigningKey
from ecdsa.util import PRNG

import hashlib

import binascii
import logging
import random
import socket
import base64
import time
import json
import os

def Hash_MAPFS(dataListByte):
    h = hashlib.new("sha256")
    result = dataListByte[0].to_bytes(32, 'big')
    for i in range(1, len(dataListByte)):
        result += (dataListByte[i].to_bytes(32, 'big'))
    h.update(result)
    HashResult = h.hexdigest()
    HashInt = int(HashResult, 16)
    Hash_value = HashInt % P256.q
    return Hash_value