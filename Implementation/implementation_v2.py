import hashlib
import time
import tracemalloc
import sys

def h(*args):
    """Egy egyszerű SHA-256 hash függvény a paraméterek összefűzésére."""
    data = "".join(str(x) for x in args).encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def puf(challenge):
    """
    A PUF (Physical Unclonable Function) szimulációja.
    A valóságban ez egy hardveres ujjlenyomat.
    """
    return h("PUF_HARDWARE_SECRET", challenge)

def measure_step(name, func, *args):
    """Mérőfüggvény a végrehajtási idő és a memóriahasználat rögzítésére."""
    tracemalloc.start()
    start_time = time.perf_counter()
    
    result = func(*args)
    
    end_time = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    elapsed_time = (end_time - start_time) * 1000 # milliszekundumban (ms)
    
    print(f"--- Lépés: {name} ---")
    print(f"Eltöltött idő: {elapsed_time:.4f} ms")
    print(f"Szükséges memória a kiszámításhoz (csúcs): {peak} bájt\n")
    
    return result

def drone_step(C_i):
    """A követő drón (D_i) inicializálási lépései."""
    R_i = puf(C_i)
    T_i = str(time.time())
    AID_i = h(R_i, T_i)
    MAC_i = h(AID_i, T_i, R_i)
    
    # A továbbítandó üzenet méretének (tárhely) kiszámítása
    storage = sys.getsizeof(AID_i) + sys.getsizeof(T_i) + sys.getsizeof(MAC_i)
    return {"AID_i": AID_i, "T_i": T_i, "MAC_i": MAC_i, "R_i": R_i}, storage

def leader_step(C_L, drone_msg):
    """A vezető drón (D_L) inicializálási lépései."""
    R_L = puf(C_L)
    T_L = str(time.time())
    AID_L = h(R_L, T_L)
    MAC_L = h(AID_L, T_L, R_L)
    
    msg_to_gs = {
        **drone_msg,
        "AID_L": AID_L,
        "T_L": T_L,
        "MAC_L": MAC_L,
        "R_L": R_L
    }
    # A Vezető Drón saját hozzájárulásának tárolási mérete
    storage = sys.getsizeof(AID_L) + sys.getsizeof(T_L) + sys.getsizeof(MAC_L)
    return msg_to_gs, storage

def gs_step(msg):
    """A földi állomás (GS) inicializálási lépései."""
    # GS megkapja és ellenőrzi a T_i és T_L időbélyegeket, majd kikeresi az R_i és R_L értékeket.
    T_GS = str(time.time())
    R_L = msg["R_L"]
    R_i = msg["R_i"]
    
    ACK_L = h(R_L, T_GS)
    Auth_L = h(R_L, ACK_L)
    ACK_i = h(R_i, Auth_L)
    M_GS = "Initialization_Points" # Szimulált pontok
    MAC_GS = h(Auth_L, ACK_i, T_GS, M_GS)
    
    gs_response = {
        "ACK_L": ACK_L,
        "Auth_L": Auth_L,
        "ACK_i": ACK_i,
        "M_GS": M_GS,
        "MAC_GS": MAC_GS,
        "T_GS": T_GS
    }
    
    # Tárolási kapacitás számítása a földi állomás válaszához
    storage = sum(sys.getsizeof(v) for v in gs_response.values())
    return gs_response, storage

def main():
    print("=== Swarm Initialization Fázis Szimuláció ===\n")
    
    C_i = "Challenge_Drone_1"
    C_L = "Challenge_Leader"
    
    # 1. Drón (D_i) végrehajtása
    drone_msg, drone_storage = measure_step("Drón (D_i) számításai", drone_step, C_i)
    
    # 2. Vezető Drón (D_L) végrehajtása
    leader_msg, leader_storage = measure_step("Vezető Drón (D_L) számításai", leader_step, C_L, drone_msg)
    
    # 3. Földi Állomás (GS) végrehajtása
    gs_msg, gs_storage = measure_step("Földi Állomás (GS) számításai", gs_step, leader_msg)
    
    # Végső eredmények kiírása
    print("=== Végeredmények tárolásához szükséges tárhely ===")
    print(f"Drón üzenetének (AID_i, T_i, MAC_i) mérete: {drone_storage} bájt")
    print(f"Vezető Drón hozzáadott üzenetének (AID_L, T_L, MAC_L) mérete: {leader_storage} bájt")
    print(f"Földi Állomás válaszának mérete: {gs_storage} bájt")
    print(f"Összes megőrzendő / továbbított adat mérete: {drone_storage + leader_storage + gs_storage} bájt")

if __name__ == "__main__":
    main()