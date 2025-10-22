# proto_bench_headless.py
import time, csv, os
import numpy as np, psutil
import importlib
import psutil

TRIALS = 300
CSV_OUT = "results_headless.csv"

# protokoll betöltése
impl = importlib.import_module("implementation")
run_fn = getattr(impl, "run_auth_once", None)

# CPU-terhelés paraméter (állítsd a drónod erejéhez)
MAT_N = 400   # 400x400 mátrixszorzás (módosítható)
REPS  = 2     # ennyiszer ismételjük a szorzást ciklusonként

first = not os.path.exists(CSV_OUT)
f = open(CSV_OUT, "a", newline="")
w = csv.writer(f)
if first:
    w.writerow(["trial","ts_iso","compute_s","auth_s","cpu_percent","mem_percent"])

A = np.random.rand(MAT_N, MAT_N).astype(np.float32)
B = np.random.rand(MAT_N, MAT_N).astype(np.float32)

for i in range(1, TRIALS+1):
    t0 = time.perf_counter()
    C = None
    for _ in range(REPS):
        C = A @ B
    comp_dt = time.perf_counter() - t0

    t1 = time.perf_counter()
    if run_fn:
        run_fn()
        auth_dt = time.perf_counter() - t1
    else:
        # fallback: ha nincs run_auth_once, a teljes implementation-t futtatjuk
        import subprocess, sys
        p = subprocess.Popen([sys.executable, "implementation.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate(timeout=60)
        auth_dt = time.perf_counter() - t1

    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent

    row = [i, time.strftime("%Y-%m-%dT%H:%M:%S"), round(comp_dt,6), round(auth_dt,6), cpu, mem]
    w.writerow(row); f.flush()
    print(f"[{i}] compute={comp_dt*1000:.1f} ms | auth={auth_dt*1000:.3f} ms | CPU={cpu:.0f}%")
f.close()
print(f"Kész. Eredmény: {CSV_OUT}")
