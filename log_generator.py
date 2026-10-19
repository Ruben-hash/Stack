"""
Variables d'environnement :
  RATE            lignes de fond par seconde          (défaut 1)
  ERROR_RATIO     part de warn/error dans le bruit    (défaut 0.15)
  INCIDENT_EVERY  secondes entre deux incidents       (défaut 120, 0 = désactivé)
"""
import os
import random
import time
from datetime import datetime, timezone

RATE = float(os.getenv("RATE", "1"))
ERROR_RATIO = float(os.getenv("ERROR_RATIO", "0.15"))
INCIDENT_EVERY = int(os.getenv("INCIDENT_EVERY", "120"))

INFO = [
    ("api", "GET /api/orders 200 in 42ms"),
    ("api", "POST /api/login 200 in 87ms"),
    ("auth", "token issued for user_id=1842"),
    ("payment", "payment processed order_id=5521 amount=49.90"),
    ("worker", "job send_email completed in 1.2s"),
    ("redis", "DB saved on disk"),
    ("nginx", "GET /health 200"),
    ("postgres", "checkpoint complete: wrote 312 buffers"),
]

# --- Problèmes isolés -------------------------------------------------------
WARN = [
    ("api", "slow request GET /api/products took 2840ms"),
    ("redis", "memory usage at 85% of maxmemory"),
    ("postgres", "too many connections: 92/100 used"),
    ("nginx", "upstream response time high: 3.1s"),
    ("worker", "job retry 2/5 for job_id=7781"),
    ("auth", "certificate expires in 6 days"),
]

ERRORS = [
    # Mauvaises configurations
    ("api", "missing required environment variable DATABASE_URL"),
    ("payment", "invalid STRIPE_API_KEY format, payments disabled"),
    ("nginx", "bind() to 0.0.0.0:80 failed (98: Address already in use)"),
    ("worker", "config file /app/config.yml not found, using defaults"),
    # Erreurs applicatives
    ("api", "unhandled exception: TypeError: Cannot read properties of undefined (reading 'id')"),
    ("auth", "JWT verification failed: invalid signature"),
    ("payment", "timeout after 30s calling https://api.stripe.com/v1/charges"),
    # Infrastructure
    ("postgres", "FATAL: password authentication failed for user app"),
    ("redis", "MISCONF Redis is configured to save RDB snapshots, but it is unable to persist on disk"),
    ("worker", "container killed: OOMKilled (memory limit 256Mi exceeded)"),
    ("postgres", "could not write to file: No space left on device"),
]

# --- Incidents en cascade (pour tester la section Dépendances) --------------
INCIDENTS = [
    [  # Base de données tombée
        ("postgres", "error", "FATAL: the database system is shutting down"),
        ("api", "error", "connect ECONNREFUSED postgres:5432"),
        ("api", "error", "GET /api/orders 500 Internal Server Error"),
        ("worker", "error", "job process_order failed: database unavailable"),
        ("nginx", "warn", "upstream api returned 502 for /api/orders"),
    ],
    [  # Redis saturé
        ("redis", "error", "OOM command not allowed when used memory > maxmemory"),
        ("auth", "error", "failed to store session: redis OOM"),
        ("api", "warn", "login failures increased: 34 in last minute"),
    ],
    [  # Disque plein
        ("postgres", "error", "could not extend file base/16384/2619: No space left on device"),
        ("payment", "error", "transaction rollback: database write failed"),
        ("api", "error", "POST /api/checkout 500"),
    ],
    [  # Certificat expiré
        ("auth", "error", "TLS handshake failed: certificate has expired"),
        ("payment", "error", "x509: certificate has expired or is not yet valid"),
        ("nginx", "error", "SSL_do_handshake() failed while SSL handshaking to upstream"),
    ],
]


def log(level: str, service: str, msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    msg = msg.replace('"', '\\"')
    print(f'ts={ts} level={level} service={service} msg="{msg}"', flush=True)


def background_line() -> None:
    if random.random() < ERROR_RATIO:
        if random.random() < 0.5:
            svc, msg = random.choice(WARN)
            log("warn", svc, msg)
        else:
            svc, msg = random.choice(ERRORS)
            log("error", svc, msg)
    else:
        svc, msg = random.choice(INFO)
        log("info", svc, msg)


def run_incident() -> None:
    for svc, level, msg in random.choice(INCIDENTS):
        log(level, svc, msg)
        time.sleep(random.uniform(0.2, 1.0))


def main() -> None:
    log("info", "log-generator", f"started rate={RATE}/s error_ratio={ERROR_RATIO} incident_every={INCIDENT_EVERY}s")
    last_incident = time.time()
    while True:
        background_line()
        if INCIDENT_EVERY > 0 and time.time() - last_incident >= INCIDENT_EVERY:
            run_incident()
            last_incident = time.time()
        time.sleep(1 / RATE)


if __name__ == "__main__":
    main()