import hashlib
import secrets
import time
from typing import Dict, List, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from functools import reduce
import sys
from sys import getsizeof
from time import time as now

# --- Parameters ---
PRIME_P = 2 ** 256 - 189  # A large prime for finite field Fp
THRESHOLD = 3

# --- Utilities ---
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def h(*args: bytes) -> bytes:
    return sha256(b"||".join(args))

# --- Mock PUF ---
def mock_puf(challenge: bytes) -> bytes:
    return sha256(challenge + b"PUF")

# --- Shamir Secret Sharing ---
def generate_polynomial(secret: int, threshold: int) -> List[int]:
    return [secret] + [secrets.randbelow(PRIME_P) for _ in range(threshold - 1)]

def evaluate_polynomial(coeffs: List[int], x: int) -> int:
    return sum(c * pow(x, i, PRIME_P) for i, c in enumerate(coeffs)) % PRIME_P

def lagrange_interpolation(points: List[Tuple[int, int]]) -> int:
    def basis(j):
        xj, _ = points[j]
        num = den = 1
        for m, (xm, _) in enumerate(points):
            if m != j:
                num = (num * (-xm)) % PRIME_P
                den = (den * (xj - xm)) % PRIME_P
        if den == 0:
            raise ValueError("Duplicate x-coordinates detected in shares, cannot interpolate.")
        return num * pow(den, PRIME_P - 2, PRIME_P) % PRIME_P

    return sum(y * basis(j) for j, (_, y) in enumerate(points)) % PRIME_P

# --- AES-GCM ---
def encrypt_message(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# --- Core Structures ---
class Drone:
    def __init__(self, drone_id: str, challenge: bytes, rank: int):
        self.id = drone_id
        self.challenge = challenge
        self.rank = rank
        self.puf_response = mock_puf(challenge)
        self.timestamp = int(time.time())
        self.aid = h(self.puf_response, str(self.timestamp).encode())
        self.mac = h(self.aid, str(self.timestamp).encode(), self.puf_response)
        self.alive = True  # used to simulate failover

    def verify_mac(self, aid: bytes, timestamp: int, mac: bytes) -> bool:
        expected_mac = h(aid, str(timestamp).encode(), self.puf_response)
        return mac == expected_mac

class GroundStation:
    def __init__(self, threshold: int):
        self.challenges: Dict[str, bytes] = {}
        self.responses: Dict[str, bytes] = {}
        self.initialization_points: List[Tuple[int, int]] = []
        self.secret = secrets.randbelow(PRIME_P)
        self.polynomial = generate_polynomial(self.secret, threshold)
        self.t = threshold

    def register_drone(self, drone: Drone):
        self.challenges[drone.id] = drone.challenge
        self.responses[drone.id] = drone.puf_response
        x = int.from_bytes(drone.puf_response, 'big') % PRIME_P
        y = evaluate_polynomial(self.polynomial, x)
        self.initialization_points.append((x, y))
        return y, self.initialization_points[:self.t - 1]  # return drone's y and init points

    def verify_authentication(self, aid: bytes, timestamp: int, mac: bytes, challenge: bytes) -> Tuple[bool, bytes]:
        expected_response = mock_puf(challenge)
        expected_aid = h(expected_response, str(timestamp).encode())
        expected_mac = h(expected_aid, str(timestamp).encode(), expected_response)
        valid = (aid == expected_aid and mac == expected_mac)
        return valid, expected_response

    def create_acknowledgment(self, RL: bytes, Ri: bytes) -> Tuple[bytes, bytes, int]:
        tgs = int(time.time())
        ackl = h(RL, str(tgs).encode())
        acki = h(Ri, h(RL, ackl))
        return ackl, acki, tgs

    def generate_drone_share(self, Ri: bytes) -> Tuple[int, int]:
        Xi = int.from_bytes(Ri, 'big') % PRIME_P
        Yi = evaluate_polynomial(self.polynomial, Xi)
        return Xi, Yi

    def reconstruct_secret(self, shares: List[Tuple[int, int]]) -> int:
        return lagrange_interpolation(shares)

# --- Main Simulation ---
if __name__ == "__main__":
    gs = GroundStation(threshold=THRESHOLD)
    drones = [Drone(f"D{i+1}", secrets.token_bytes(16), i) for i in range(THRESHOLD)]

    print("--- Predeployment ---")
    all_shares = []
    init_points = None
    for d in drones:
        y, init_points = gs.register_drone(d)
        x = int.from_bytes(d.puf_response, 'big') % PRIME_P
        all_shares.append((x, y))
        print(f"Drone {d.id}: Challenge stored, Share ({x}, {y})")

    step_times = {}
    data_sizes = {"total_sent": 0, "total_stored": 0}

    print("\n--- Swarm Initialization with Leader Failover ---")
    start = now()

    print("[Step 1] Leader Election")
    t1 = now()
    drones.sort(key=lambda d: d.rank)
    leader = next((d for d in drones if d.alive), None)
    print(f"Initial Leader: {leader.id}")
    step_times['Leader Election'] = now() - t1

    print("\n[Step 2] Simulating Leader Failure")
    t2 = now()
    leader.alive = False
    print(f"{leader.id} has failed! Initiating failover...")
    leader = next((d for d in drones if d.alive), None)
    print(f"New Leader: {leader.id}")
    step_times['Failover'] = now() - t2

    print("\n[Step 3] Drones Authenticate to the Ground Station")
    t3 = now()
    auth_data = []
    for d in drones:
        if not d.alive:
            continue
        aid = d.aid
        mac = d.mac
        timestamp = d.timestamp
        valid, Ri = gs.verify_authentication(aid, timestamp, mac, d.challenge)
        auth_data.append((d.id, valid, Ri))
        data_sizes['total_sent'] += sum(map(getsizeof, [aid, mac, timestamp]))
        print(f"Drone {d.id}: Authentication {'succeeded' if valid else 'failed'}")
    step_times['Authentication'] = now() - t3

    print("\n[Step 4] Ground Station Creates ACKs and Shares")
    t4 = now()
    for d_id, valid, Ri in auth_data:
        if not valid:
            continue
        RL = mock_puf(gs.challenges[leader.id])
        ackl, acki, tgs = gs.create_acknowledgment(RL, Ri)
        Xi, Yi = gs.generate_drone_share(Ri)
        share = (Xi, Yi)
        data_sizes['total_sent'] += sum(map(getsizeof, [ackl, acki, tgs, Xi, Yi]))
        data_sizes['total_stored'] += getsizeof(gs.challenges[d_id]) + getsizeof(Ri) + getsizeof((Xi, Yi))
        print(f"Drone {d_id}: ACKL: {ackl.hex()[:8]}, ACKi: {acki.hex()[:8]} | Share: {share}")
    step_times['ACK and Share Creation'] = now() - t4

    print("\n[Step 5] Reconstructing Shared Secret Key")
    t5 = now()
    reconstructed_secret = gs.reconstruct_secret(all_shares)
    key = reconstructed_secret.to_bytes(32, 'big')
    print("Shared Key:", key.hex())
    step_times['Key Reconstruction'] = now() - t5

    total_time = now() - start

    print("\n--- Communication Phase ---")
    t6 = now()
    message = b"Drone telemetry: Altitude 120m, Speed 15m/s"
    nonce, ciphertext, tag = encrypt_message(key, message)
    decrypted = decrypt_message(key, nonce, ciphertext, tag)
    print("Encrypted:", ciphertext.hex())
    print("Decrypted:", decrypted.decode())
    step_times['Communication'] = now() - t6

    print("\n--- Performance Metrics ---")
    for step, duration in step_times.items():
        print(f"{step}: {duration:.6f} seconds")
    print(f"Total Initialization Time: {total_time:.6f} seconds")
    print(f"Data Sent: {data_sizes['total_sent']} bytes")
    print(f"Data Stored: {data_sizes['total_stored']} bytes")
