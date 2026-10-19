#!/usr/bin/env python3
"""
analyse_logs.py
Loki  ->  nettoyage + dédoublonnage  ->  LM Studio (API OpenAI)  ->  rapport Markdown

Bibliothèque standard uniquement : tourne tel quel dans python:3.12-alpine.

Exemples :
    python analyse_logs.py                     # dernière heure, warn et plus
    python analyse_logs.py --since 15m --min-level error
    python analyse_logs.py --query '{container="log-generator"}' --no-llm

Variables d'environnement :
    LOKI_URL   (défaut http://localhost:3100)
    LLM_URL    (défaut http://localhost:1235/v1)
    LLM_MODEL  (défaut phi-4-mini-reasoning)
    LLM_API_KEY (défaut lm-studio, ignorée par LM Studio)
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100").rstrip("/")
LLM_URL = os.getenv("LLM_URL", "http://localhost:1235/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "phi-4-mini-reasoning")
LLM_API_KEY = os.getenv("LLM_API_KEY", "lm-studio")

LEVEL_ORDER = {"debug": 0, "info": 1, "unknown": 1, "warn": 2, "error": 3, "critical": 4}
LEVEL_ALIASES = {
    "trace": "debug", "debug": "debug", "dbg": "debug",
    "info": "info", "information": "info", "notice": "info",
    "warn": "warn", "warning": "warn",
    "error": "error", "err": "error",
    "crit": "critical", "critical": "critical", "fatal": "critical",
    "panic": "critical", "emerg": "critical", "alert": "critical",
}


# --------------------------------------------------------------------------- #
# Outils HTTP
# --------------------------------------------------------------------------- #
def http_json(url, payload=None, timeout=30, headers=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    hdrs = {"Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def parse_duration(text):
    m = re.fullmatch(r"(\d+)\s*([smhd])", text.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError("durée invalide (ex : 30s, 15m, 1h, 2d)")
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


# --------------------------------------------------------------------------- #
# 1. Extraction depuis Loki
# --------------------------------------------------------------------------- #
def detect_query():
    """Construit une requête LogQL qui prend tout, selon les labels présents."""
    labels = http_json(f"{LOKI_URL}/loki/api/v1/labels").get("data") or []
    for label in ("container", "container_name", "service_name", "service", "job", "filename"):
        if label in labels:
            return f'{{{label}=~".+"}}'
    if labels:
        return f'{{{labels[0]}=~".+"}}'
    raise RuntimeError("Loki ne renvoie aucun label : aucun log ingéré sur la période ?")


def fetch_logs(query, start, end, max_lines, page_size=5000):
    """Récupère les logs avec pagination (Loki limite à 5000 lignes par requête)."""
    entries = []
    cursor = int(start.timestamp() * 1e9)
    end_ns = int(end.timestamp() * 1e9)

    while len(entries) < max_lines and cursor < end_ns:
        limit = min(page_size, max_lines - len(entries))
        params = urllib.parse.urlencode({
            "query": query, "start": cursor, "end": end_ns,
            "limit": limit, "direction": "forward",
        })
        result = http_json(f"{LOKI_URL}/loki/api/v1/query_range?{params}", timeout=60)
        streams = result.get("data", {}).get("result", [])

        batch = []
        for stream in streams:
            labels = stream.get("stream", {})
            for ts, line in stream.get("values", []):
                batch.append((int(ts), labels, line))
        if not batch:
            break

        batch.sort(key=lambda e: e[0])
        entries.extend(batch)
        if len(batch) < limit:
            break
        cursor = batch[-1][0] + 1

    return entries[:max_lines]


# --------------------------------------------------------------------------- #
# 2. Nettoyage
# --------------------------------------------------------------------------- #
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
LEVEL_RE = re.compile(
    r"\b(trace|debug|info|notice|warn(?:ing)?|error|err|crit(?:ical)?|fatal|panic)\b", re.I
)
LEVEL_KEYS = ("level", "lvl", "severity", "levelname", "log.level", "loglevel")
MSG_KEYS = ("msg", "message", "log", "text", "event", "error")
SERVICE_KEYS = ("service", "service_name", "app", "component", "logger")
LABEL_SERVICE_KEYS = ("service_name", "service", "container", "container_name", "app", "job")


def normalize_level(raw):
    if raw is None:
        return None
    return LEVEL_ALIASES.get(str(raw).strip().lower())


def clean_entry(ts, labels, line):
    line = ANSI_RE.sub("", line).replace("\x00", "").strip()
    if not line:
        return None

    level, msg, service = None, line, None

    # Logs JSON (log_generator, flog, la plupart des applis modernes)
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            level = next((normalize_level(obj[k]) for k in LEVEL_KEYS if k in obj), None)
            service = next((str(obj[k]) for k in SERVICE_KEYS if obj.get(k)), None)
            msg = next((obj[k] for k in MSG_KEYS if obj.get(k)), None)
            if msg is None:  # pas de champ message : on garde les champs utiles
                msg = " ".join(f"{k}={v}" for k, v in obj.items()
                               if k not in LEVEL_KEYS and k not in ("time", "timestamp", "ts"))

    if level is None:
        level = normalize_level(labels.get("level")) or normalize_level(labels.get("detected_level"))
    if level is None:
        m = LEVEL_RE.search(line[:200])
        level = normalize_level(m.group(1)) if m else "unknown"

    if not service:
        service = next((labels[k] for k in LABEL_SERVICE_KEYS if labels.get(k)), "inconnu")
    service = str(service).lstrip("/")

    msg = re.sub(r"\s+", " ", str(msg)).strip()
    return {"ts": ts, "service": service, "level": level, "msg": msg}


# --------------------------------------------------------------------------- #
# 3. Dédoublonnage / regroupement
# --------------------------------------------------------------------------- #
SIGNATURE_PATTERNS = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<UUID>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I), "<HEX>"),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|m|h|kb|mb|gb|%)?\b", re.I), "<N>"),
]


def signature(msg):
    """Remplace les parties variables pour regrouper les messages identiques sur le fond."""
    sig = msg
    for pattern, repl in SIGNATURE_PATTERNS:
        sig = pattern.sub(repl, sig)
    return sig


def deduplicate(entries):
    # a) doublons exacts (même horodatage, service et message)
    seen, unique = set(), []
    for e in entries:
        key = (e["ts"], e["service"], e["msg"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    # b) regroupement par signature
    groups = {}
    for e in unique:
        key = (e["service"], e["level"], signature(e["msg"]))
        g = groups.get(key)
        if g is None:
            groups[key] = {"service": e["service"], "level": e["level"], "signature": key[2],
                           "example": e["msg"], "count": 1, "first": e["ts"], "last": e["ts"]}
        else:
            g["count"] += 1
            g["first"] = min(g["first"], e["ts"])
            g["last"] = max(g["last"], e["ts"])

    ordered = sorted(groups.values(),
                     key=lambda g: (-LEVEL_ORDER.get(g["level"], 1), -g["count"]))
    return unique, ordered, len(entries) - len(unique)


# --------------------------------------------------------------------------- #
# 4. Analyse par LM Studio
# --------------------------------------------------------------------------- #
def fmt_ts(ns, fmt="%d/%m %H:%M:%S"):
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).astimezone().strftime(fmt)


def build_prompt(groups, stats, start, end, top, max_chars):
    lines = []
    for g in groups[:top]:
        ex = g["example"]
        if len(ex) > max_chars:
            ex = ex[:max_chars] + "…"
        lines.append(f"- [{g['level'].upper()}] {g['service']} ×{g['count']} "
                     f"(de {fmt_ts(g['first'], '%H:%M:%S')} à {fmt_ts(g['last'], '%H:%M:%S')}) : {ex}")

    by_level = ", ".join(f"{k}={v}" for k, v in stats["by_level"].most_common())
    system = (
        "Tu es un ingénieur SRE expérimenté. Tu analyses des logs applicatifs déjà regroupés. "
        "Tu réponds en français, en Markdown, de façon factuelle et concise. "
        "Tu ne t'appuies que sur les logs fournis et tu n'inventes ni service ni chiffre."
    )
    user = (
        f"Période : {start:%d/%m/%Y %H:%M} → {end:%d/%m/%Y %H:%M}\n"
        f"Lignes uniques : {stats['unique']} | Répartition par niveau : {by_level}\n\n"
        f"Messages les plus importants (niveau, service, nombre d'occurrences, exemple) :\n"
        + "\n".join(lines)
        + "\n\nRédige l'analyse avec exactement ces sections (titres de niveau ###) :\n"
        "### Résumé\n(3 phrases maximum : état général du système)\n"
        "### Incidents principaux\n(pour chacun : service, symptôme, cause probable, impact)\n"
        "### Corrélations\n(enchaînements ou effets en cascade entre services, s'il y en a)\n"
        "### Actions recommandées\n(liste priorisée, de la plus urgente à la moins urgente)"
    )
    return system, user


def strip_reasoning(text):
    """Les modèles 'reasoning' renvoient parfois leur réflexion entre <think>…</think>."""
    if "</think>" in text:
        text = text.split("</think>", 1)[1]
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    return text.strip()


def ask_llm(system, user, max_tokens, timeout):
    payload = {
        "model": LLM_MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": 0.2,
        "max_tokens": max_tokens,
        "stream": False,
    }
    data = http_json(f"{LLM_URL}/chat/completions", payload, timeout=timeout,
                     headers={"Authorization": f"Bearer {LLM_API_KEY}"})
    content = data["choices"][0]["message"].get("content") or ""
    return strip_reasoning(content), data.get("usage", {})


# --------------------------------------------------------------------------- #
# 5. Rapport Markdown
# --------------------------------------------------------------------------- #
def md_cell(text, limit=160):
    text = text.replace("|", "\\|").replace("`", "'").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"


def build_report(args, query, start, end, stats, groups, analysis, usage):
    out = []
    now = datetime.now().astimezone()
    out.append("# Rapport d'analyse des logs\n")
    out.append(f"_Généré le {now:%d/%m/%Y à %H:%M:%S}_\n")

    out.append("## Période analysée\n")
    out.append("| Paramètre | Valeur |\n|---|---|")
    out.append(f"| Début | {start.astimezone():%d/%m/%Y %H:%M:%S} |")
    out.append(f"| Fin | {end.astimezone():%d/%m/%Y %H:%M:%S} |")
    out.append(f"| Requête LogQL | `{md_cell(query)}` |")
    out.append(f"| Source | {LOKI_URL} |")
    out.append(f"| Modèle | {'— (analyse IA désactivée)' if args.no_llm else LLM_MODEL} |\n")

    out.append("## Statistiques\n")
    out.append("| Indicateur | Valeur |\n|---|---|")
    out.append(f"| Lignes récupérées | {stats['raw']} |")
    out.append(f"| Lignes vides ou illisibles écartées | {stats['dropped']} |")
    out.append(f"| Doublons exacts supprimés | {stats['duplicates']} |")
    out.append(f"| Lignes uniques | {stats['unique']} |")
    out.append(f"| Messages distincts (après regroupement) | {len(groups)} |\n")

    out.append("### Par niveau\n")
    out.append("| Niveau | Lignes |\n|---|---|")
    for lvl, n in sorted(stats["by_level"].items(), key=lambda kv: -LEVEL_ORDER.get(kv[0], 1)):
        out.append(f"| {lvl} | {n} |")
    out.append("")

    out.append("### Par service\n")
    out.append("| Service | Total | Warn | Error / Critical |\n|---|---|---|---|")
    for svc, counts in sorted(stats["by_service"].items(), key=lambda kv: -sum(kv[1].values())):
        total = sum(counts.values())
        err = counts.get("error", 0) + counts.get("critical", 0)
        out.append(f"| {md_cell(svc, 60)} | {total} | {counts.get('warn', 0)} | {err} |")
    out.append("")

    out.append("## Analyse IA\n")
    if args.no_llm:
        out.append("_Analyse IA désactivée (`--no-llm`)._\n")
    else:
        out.append(analysis.strip() + "\n")
        if usage:
            out.append(f"_Tokens : {usage.get('prompt_tokens', '?')} en entrée, "
                       f"{usage.get('completion_tokens', '?')} en sortie._\n")

    shown = [g for g in groups if LEVEL_ORDER.get(g["level"], 1) >= LEVEL_ORDER[args.min_level]]
    out.append(f"## Messages les plus fréquents (niveau ≥ {args.min_level})\n")
    if not shown:
        out.append("_Aucun message à ce niveau sur la période._\n")
    else:
        out.append("| Niveau | Service | Occurrences | Premier | Dernier | Exemple |")
        out.append("|---|---|---|---|---|---|")
        for g in shown[:args.table_rows]:
            out.append(f"| {g['level']} | {md_cell(g['service'], 40)} | {g['count']} | "
                       f"{fmt_ts(g['first'])} | {fmt_ts(g['last'])} | {md_cell(g['example'])} |")
        out.append("")

    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(description="Analyse des logs Loki avec LM Studio → rapport Markdown")
    p.add_argument("--since", type=parse_duration, default=parse_duration("1h"),
                   help="période à analyser jusqu'à maintenant (30s, 15m, 1h, 2d). Défaut : 1h")
    p.add_argument("--query", help="requête LogQL (défaut : détectée selon les labels Loki)")
    p.add_argument("--max-lines", type=int, default=20000, help="lignes max récupérées. Défaut : 20000")
    p.add_argument("--min-level", choices=["debug", "info", "warn", "error", "critical"], default="warn",
                   help="niveau minimum envoyé au LLM et affiché dans le tableau. Défaut : warn")
    p.add_argument("--top", type=int, default=30, help="nombre de messages envoyés au LLM. Défaut : 30")
    p.add_argument("--max-chars", type=int, default=250, help="longueur max d'un exemple envoyé au LLM")
    p.add_argument("--max-tokens", type=int, default=2000, help="tokens max de la réponse du LLM")
    p.add_argument("--timeout", type=int, default=600, help="délai max d'attente du LLM, en secondes")
    p.add_argument("--table-rows", type=int, default=25, help="lignes du tableau final. Défaut : 25")
    p.add_argument("--output-dir", default="reports", help="dossier des rapports. Défaut : reports")
    p.add_argument("--no-llm", action="store_true", help="ne pas appeler LM Studio")
    args = p.parse_args()

    end = datetime.now(timezone.utc)
    start = end - args.since

    # 1. Extraction
    try:
        query = args.query or detect_query()
        print(f"[1/4] Loki {LOKI_URL} — requête {query} sur {args.since}", flush=True)
        raw = fetch_logs(query, start, end, args.max_lines)
    except (urllib.error.URLError, OSError, RuntimeError) as exc:
        sys.exit(f"Erreur Loki : {exc}")
    print(f"      {len(raw)} lignes récupérées", flush=True)
    if not raw:
        sys.exit("Aucun log sur la période : rien à analyser.")

    # 2. Nettoyage
    cleaned = [c for c in (clean_entry(*e) for e in raw) if c]
    print(f"[2/4] Nettoyage : {len(raw) - len(cleaned)} lignes écartées", flush=True)

    # 3. Dédoublonnage
    unique, groups, duplicates = deduplicate(cleaned)
    stats = {
        "raw": len(raw), "dropped": len(raw) - len(cleaned), "duplicates": duplicates,
        "unique": len(unique), "by_level": Counter(e["level"] for e in unique),
        "by_service": defaultdict(Counter),
    }
    for e in unique:
        stats["by_service"][e["service"]][e["level"]] += 1
    print(f"[3/4] {duplicates} doublons supprimés, {len(groups)} messages distincts", flush=True)

    # 4. Analyse IA
    analysis, usage = "", {}
    if not args.no_llm:
        min_rank = LEVEL_ORDER[args.min_level]
        selected = [g for g in groups if LEVEL_ORDER.get(g["level"], 1) >= min_rank]
        if not selected:
            analysis = f"Aucun message de niveau {args.min_level} ou supérieur sur la période : rien d'anormal."
        else:
            system, user = build_prompt(selected, stats, start.astimezone(), end.astimezone(),
                                        args.top, args.max_chars)
            print(f"[4/4] Envoi de {min(len(selected), args.top)} messages à {LLM_MODEL} "
                  f"({LLM_URL})…", flush=True)
            try:
                analysis, usage = ask_llm(system, user, args.max_tokens, args.timeout)
                if not analysis:
                    analysis = "_Le modèle n'a renvoyé aucun texte (augmenter --max-tokens ?)._"
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:500]
                analysis = f"_Erreur LM Studio (HTTP {exc.code}) : {md_cell(detail, 500)}_"
            except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
                analysis = f"_Erreur LM Studio : {exc}_"
            print("      " + ("échec, voir le rapport" if analysis.startswith("_Erreur") else "réponse reçue"),
                  flush=True)
    else:
        print("[4/4] Analyse IA ignorée (--no-llm)", flush=True)

    # 5. Rapport
    report = build_report(args, query, start, end, stats, groups, analysis, usage)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"rapport_logs_{datetime.now():%Y%m%d_%H%M%S}.md"
    path.write_text(report, encoding="utf-8")
    print(f"Rapport écrit : {path}")


if __name__ == "__main__":
    main()