# proto_bench_headless_mem.py
import time, csv, os, sys, gc
import numpy as np, psutil

TRIALS = 300
CSV_OUT = "results_headless_mem.csv"

# --- protokoll betöltése (preferált: implementation.run_auth_once) -----------
import importlib, subprocess
impl = importlib.import_module("implementation")
run_fn = getattr(impl, "run_auth_once", None)
PY = sys.executable

def run_auth_once():
    if run_fn:
        t0 = time.perf_counter()
        run_fn()
        return time.perf_counter() - t0
    # fallback: teljes implementation.py fut, falidőt mérünk
    t0 = time.perf_counter()
    p = subprocess.Popen([PY, "implementation_v2.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.communicate(timeout=60)
    return time.perf_counter() - t0

# --- compute terhelés paraméterek (állíthatóak a "drón érzethez") ------------
MAT_N = 400   # mátrix méret
REPS  = 2     # szorzások száma iterációnként

A = np.random.rand(MAT_N, MAT_N).astype(np.float32)
B = np.random.rand(MAT_N, MAT_N).astype(np.float32)

# --- folyamat/memória mérés előkészítés --------------------------------------
proc = psutil.Process(os.getpid())

def get_mem_snapshot():
    """Visszaad: rss_mb, vms_mb, peak_rss_mb (ha van), sys_mem_percent."""
    mi = proc.memory_info()               # rss, vms
    rss_mb = mi.rss / (1024*1024)
    vms_mb = mi.vms / (1024*1024)
    # rendszer memória
    sys_mem_percent = psutil.virtual_memory().percent
    # peak (Windows: memory_full_info().peak_wset), más OS-en lehet nincs
    peak_rss_mb = None
    try:
        mfull = proc.memory_full_info()
        # Windows: peak_wset (bytes); Linux: peak_rss nem mindig elérhető
        if hasattr(mfull, "peak_wset") and mfull.peak_wset:
            peak_rss_mb = mfull.peak_wset / (1024*1024)
        elif hasattr(mfull, "peak_rss") and mfull.peak_rss:
            peak_rss_mb = mfull.peak_rss / (1024*1024)
    except Exception:
        pass
    return rss_mb, vms_mb, peak_rss_mb, sys_mem_percent

# --- CSV fejléc ---------------------------------------------------------------
first = not os.path.exists(CSV_OUT)
f = open(CSV_OUT, "a", newline="")
w = csv.writer(f)
if first:
    w.writerow([
        "trial","ts_iso",
        "compute_s","auth_s",
        "cpu_percent",
        "sys_mem_percent",
        "rss_mb","rss_delta_kb","vms_mb","peak_rss_mb"
    ])

print("Mérés indul... (Headless compute + protokoll + memória)")
prev_rss_mb = None

# opcionális: minimalizáld GC-zajt a mérés elején
gc.collect()

for i in range(1, TRIALS+1):
    # --- compute terhelés ---
    t0 = time.perf_counter()
    C = None
    for _ in range(REPS):
        C = A @ B
    compute_dt = time.perf_counter() - t0

    # --- protokoll ---
    auth_dt = run_auth_once()

    # --- metrikák ---
    cpu = psutil.cpu_percent(interval=None)
    rss_mb, vms_mb, peak_rss_mb, sys_mem = get_mem_snapshot()

    if prev_rss_mb is None:
        rss_delta_kb = 0.0
    else:
        rss_delta_kb = (rss_mb - prev_rss_mb) * 1024  # MB -> KiB
    prev_rss_mb = rss_mb

    # opcionális: hosszabb futásoknál néha GC
    if i % 50 == 0:
        gc.collect()

    row = [
        i, time.strftime("%Y-%m-%dT%H:%M:%S"),
        round(compute_dt,6), round(auth_dt,6),
        cpu,
        sys_mem,
        round(rss_mb,3), round(rss_delta_kb,1), round(vms_mb,3),
        (round(peak_rss_mb,3) if peak_rss_mb is not None else "")
    ]
    w.writerow(row); f.flush()

    print(f"[{i}] comp={compute_dt*1000:.2f} ms | auth={auth_dt*1000:.3f} ms | "
          f"CPU={cpu:.0f}% | RSS={rss_mb:.2f} MB (Δ {rss_delta_kb:.1f} KiB) | VMS={vms_mb:.2f} MB")

f.close()
print(f"Kész: {CSV_OUT}")
