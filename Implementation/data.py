import os
import time
import sys
import tracemalloc
import statistics
from dataclasses import dataclass
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ==========================================================
# Utility functions
# ==========================================================

def current_time_ns():
    return time.perf_counter_ns()


def sizeof(obj):
    return sys.getsizeof(obj)


def serialize_public_key(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


# ==========================================================
# PUF Simulation (Realistic but software-based)
# ==========================================================

class SimulatedPUF:
    """
    Simulates a hardware PUF using device-unique seed.
    """

    def __init__(self):
        self.device_secret = os.urandom(32)

    def response(self, challenge: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.device_secret)
        digest.update(challenge)
        return digest.finalize()


# ==========================================================
# Drone
# ==========================================================

class Drone:

    def __init__(self, drone_id: str):
        self.id = drone_id
        self.puf = SimulatedPUF()

        # Long-term ECC key pair
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def generate_init_message(self):
        challenge = os.urandom(16)
        puf_resp = self.puf.response(challenge)

        message = {
            "drone_id": self.id,
            "challenge": challenge,
            "puf_response": puf_resp,
            "pub_key": serialize_public_key(self.public_key)
        }

        return message


# ==========================================================
# Leader
# ==========================================================

class Leader:

    def __init__(self, leader_id: str):
        self.id = leader_id
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def verify_and_forward(self, drone_msg: Dict):

        # Simulate verification cost
        time.sleep(0)

        forward_msg = {
            "leader_id": self.id,
            "drone_payload": drone_msg,
            "leader_pub": serialize_public_key(self.public_key)
        }

        return forward_msg


# ==========================================================
# Ground Station
# ==========================================================

class GroundStation:

    def __init__(self):
        self.registered_drones: Dict[str, bytes] = {}

    def register_drone(self, drone: Drone):
        self.registered_drones[drone.id] = serialize_public_key(drone.public_key)

    def process_initialization(self, msg: Dict):

        drone_payload = msg["drone_payload"]
        drone_id = drone_payload["drone_id"]

        if drone_id not in self.registered_drones:
            raise Exception("Unknown drone")

        # ECDH key agreement
        drone_pub_bytes = drone_payload["pub_key"]
        drone_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            drone_pub_bytes
        )

        gs_private = ec.generate_private_key(ec.SECP256R1())

        shared_key = gs_private.exchange(ec.ECDH(), drone_pub)

        # Derive session key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"swarm-init",
        ).derive(shared_key)

        return derived_key


# ==========================================================
# Swarm Initialization Execution
# ==========================================================

def swarm_initialization():
    drone = Drone("D1")
    leader = Leader("L1")
    gs = GroundStation()

    gs.register_drone(drone)

    msg1 = drone.generate_init_message()
    msg2 = leader.verify_and_forward(msg1)
    session_key = gs.process_initialization(msg2)

    return msg1, msg2, session_key


# ==========================================================
# Benchmarking
# ==========================================================

def benchmark(runs=100):

    time_results = []
    memory_results = []
    message_sizes = []

    for _ in range(runs):

        tracemalloc.start()
        start = current_time_ns()

        msg1, msg2, sk = swarm_initialization()

        end = current_time_ns()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        time_results.append((end - start) / 1e6)  # ms
        memory_results.append(peak)
        message_sizes.append(sizeof(msg1) + sizeof(msg2))

    print("===== Swarm Initialization Benchmark =====")
    print(f"Runs: {runs}")
    print(f"Average Time: {statistics.mean(time_results):.3f} ms")
    print(f"Average Peak Memory: {statistics.mean(memory_results)/1024:.2f} KB")
    print(f"Average Message Size (approx): {statistics.mean(message_sizes)} bytes")
    print("===========================================")


# ==========================================================
# Run benchmark
# ==========================================================

if __name__ == "__main__":
    benchmark(200)
