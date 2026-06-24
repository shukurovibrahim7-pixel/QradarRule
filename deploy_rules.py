#!/usr/bin/env python3
"""
deploy_rules.py
===============
GitHub-da yazılmış Sigma rule-ları AQL-ə çevirib QRadar-a push edən skript.
Task 15 - QRadar Offense Rules, Network Flow, Alert Yaradılması

İstifadə:
    python3 deploy_rules.py

Mühit dəyişənləri (Environment Variables):
    QRADAR_HOST       - QRadar-ın IP/hostname (məs: 192.168.1.100)
    QRADAR_API_TOKEN  - QRadar API Token (SEC token)
    RULES_DIR         - Rule fayllarının olduğu qovluq (default: ./rules)
"""

import os
import sys
import json
import glob
import time
import logging
import requests
import urllib3
import yaml

# SSL xəbərdarlıqlarını deaktiv edirik (lab mühiti üçün)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Logging konfiqurasiyası ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("deploy_rules.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


# ─── Konfiqurasiya ─────────────────────────────────────────────────────────────
QRADAR_HOST      = os.environ.get("51.21.74.45", "")
QRADAR_API_TOKEN = os.environ.get("e8465730-610a-4290-ad3a-86fb9b117caf", "")
RULES_DIR        = os.environ.get("RULES_DIR", "./rule")
API_VERSION      = "17.0"          # QRadar REST API versiyası
REQUEST_TIMEOUT  = 30              # saniyə
RETRY_COUNT      = 3               # şəbəkə xətası zamanı yenidən cəhd sayı
RETRY_DELAY      = 5               # yenidən cəhd arası gözləmə (saniyə)


# ─── Sigma → AQL Konvertoru ────────────────────────────────────────────────────
SIGMA_FIELD_MAP: dict[str, str] = {
    # Windows EventLog sahə uyğunluqları
    "EventID":          "QIDNAME(qid)",
    "CommandLine":      "\"Process CommandLine\"",
    "Image":            "\"Process Image\"",
    "ParentImage":      "\"Parent Image\"",
    "User":             "username",
    "TargetUserName":   "username",
    "SourceIp":         "sourceip",
    "DestinationIp":    "destinationip",
    "DestinationPort":  "destinationport",
    "SourcePort":       "sourceport",
    "FileName":         "filename",
    "Hashes":           "filehash",
    "ServiceName":      "\"Service Name\"",
    "QueryName":        "\"DNS QueryName\"",
    "sha256":           "filehash",
    # Syslog
    "message":          "\"UTF8(payload)\"",
    "msg":              "\"UTF8(payload)\"",
}

SIGMA_CONDITION_OPS: dict[str, str] = {
    "|contains":    "ILIKE '%%{value}%%'",
    "|startswith":  "ILIKE '{value}%%'",
    "|endswith":    "ILIKE '%%{value}'",
    "|re":          "MATCHES '{value}'",
    "":             "= '{value}'",
}


def _map_field(sigma_field: str) -> str:
    """Sigma sahəsini AQL sahəsinə çevirir."""
    return SIGMA_FIELD_MAP.get(sigma_field, f'"{sigma_field}"')


def _build_condition(field: str, value, modifier: str = "") -> str:
    """Tək bir Sigma şərtini AQL ifadəsinə çevirir."""
    aql_field = _map_field(field)
    template   = SIGMA_CONDITION_OPS.get(modifier, "= '{value}'")

    if isinstance(value, list):
        parts = [template.format(value=v) for v in value]
        return f"({aql_field} {' OR ' + aql_field + ' '.join(parts)})"

    return f"{aql_field} {template.format(value=value)}"


def _parse_detection(detection: dict) -> str:
    """
    Sigma detection blokundan AQL WHERE şərtini qurur.
    Sadə 1-2 selector dəstəkləyir; condition: selection
    """
    conditions: list[str] = []

    for selector, criteria in detection.items():
        if selector == "condition":
            continue
        if not isinstance(criteria, dict):
            continue

        selector_parts: list[str] = []
        for raw_field, values in criteria.items():
            # modifier ayırmaq: CommandLine|contains -> ("CommandLine", "|contains")
            parts   = raw_field.split("|", 1)
            field   = parts[0]
            mod     = f"|{parts[1]}" if len(parts) > 1 else ""
            part    = _build_condition(field, values, mod)
            selector_parts.append(part)

        conditions.append(" AND ".join(selector_parts))

    condition_str = detection.get("condition", "selection")
    # Sadə "selection" və "selection1 and selection2" halları
    if "and" in condition_str:
        return " AND ".join(conditions)
    return " OR ".join(conditions) if len(conditions) > 1 else (conditions[0] if conditions else "1=1")


def sigma_to_aql(sigma_file: str) -> dict | None:
    """
    Sigma YAML faylını oxuyub AQL formatına çevirir.

    Returns:
        {name, description, aql_query} və ya None (xəta zamanı)
    """
    try:
        with open(sigma_file, "r", encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
    except Exception as exc:
        log.error("Sigma faylı oxunmadı (%s): %s", sigma_file, exc)
        return None

    title       = rule.get("title", os.path.basename(sigma_file))
    description = rule.get("description", "")
    detection   = rule.get("detection", {})
    timeframe   = rule.get("detection", {}).get("timeframe", "LAST 24 HOURS")
    log_source  = rule.get("logsource", {})

    # Zaman çərçivəsi normallaşdırması (15m → LAST 15 MINUTES)
    tf_clean = timeframe
    if isinstance(timeframe, str):
        tf_clean = (
            timeframe
            .replace("m", " MINUTES")
            .replace("h", " HOURS")
            .replace("d", " DAYS")
        )

    try:
        where_clause = _parse_detection(detection)
    except Exception as exc:
        log.warning("Detection parse xətası (%s): %s — boş WHERE istifadə edilir", sigma_file, exc)
        where_clause = "1=1"

    # Log mənbəyi filtri
    log_filter = ""
    category   = log_source.get("category", "")
    product    = log_source.get("product", "")
    if product == "windows":
        log_filter = "logsourcename ILIKE '%%Windows%%' AND "
    elif category == "network":
        log_filter = "logsourcename ILIKE '%%firewall%%' OR logsourcename ILIKE '%%flow%%' AND "

    aql = (
        f"SELECT UTF8(payload) AS 'Raw Event', "
        f"sourceip, destinationip, username, "
        f"QIDNAME(qid) AS 'Event Name', "
        f"logsourcename(logsourceid) AS 'Log Source' "
        f"FROM events "
        f"WHERE {log_filter}{where_clause} "
        f"LAST {tf_clean if 'LAST' not in tf_clean else tf_clean.replace('LAST ', '')} "
        f"ORDER BY starttime DESC"
    )

    return {"name": title, "description": description, "aql_query": aql}


# ─── QRadar API ───────────────────────────────────────────────────────────────
class QRadarClient:
    """QRadar REST API ilə işləyən sadə client."""

    def __init__(self, host: str, token: str):
        if not host or not token:
            raise ValueError(
                "QRADAR_HOST və QRADAR_API_TOKEN mühit dəyişənlərini təyin edin!"
            )
        self.base_url = f"https://{host}/api"
        self.headers  = {
            "SEC":          token,
            "Content-Type": "application/json",
            "Accept":       "application/json",
            "Version":      API_VERSION,
        }

    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Retry mexanizmi ilə HTTP sorğu göndərir."""
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, RETRY_COUNT + 1):
            try:
                resp = requests.request(
                    method, url,
                    headers=self.headers,
                    verify=False,
                    timeout=REQUEST_TIMEOUT,
                    **kwargs,
                )
                return resp
            except requests.exceptions.RequestException as exc:
                log.warning("Sorğu xətası (cəhd %d/%d): %s", attempt, RETRY_COUNT, exc)
                if attempt < RETRY_COUNT:
                    time.sleep(RETRY_DELAY)
        raise ConnectionError(f"QRadar API-yə qoşulmaq mümkün olmadı: {url}")

    def test_connection(self) -> bool:
        """API əlaqəsini yoxlayır."""
        try:
            resp = self._request("GET", "/system/about")
            if resp.status_code == 200:
                info = resp.json()
                log.info("QRadar bağlantısı uğurlu: versiyan=%s", info.get("release_name", "?"))
                return True
            log.error("Bağlantı xətası: HTTP %d — %s", resp.status_code, resp.text)
            return False
        except Exception as exc:
            log.error("Bağlantı testi uğursuz: %s", exc)
            return False

    def get_existing_rules(self) -> dict[str, int]:
        """Mövcud rule-ların {name: id} xəritəsini qaytarır."""
        resp  = self._request("GET", "/analytics/rules?fields=id,name")
        rules = {}
        if resp.status_code == 200:
            for rule in resp.json():
                rules[rule["name"]] = rule["id"]
        else:
            log.warning("Rule siyahısı alınmadı: HTTP %d", resp.status_code)
        return rules

    def create_rule(self, name: str, aql_query: str, description: str = "") -> bool:
        """Yeni offense rule yaradır."""
        payload = {
            "name":        name,
            "type":        "COMMON",
            "enabled":     True,
            "notes":       description,
            "tests":       [
                {
                    "type":       "AND",
                    "name":       "AQL Filter",
                    "id":         1,
                    "uid":        "AQL_FILTER",
                    "parameters": [{"name": "Query", "value": aql_query}],
                    "group_functions": [],
                }
            ],
            "actions":     [],
            "responses":   [],
            "building_blocks": [],
        }
        resp = self._request("POST", "/analytics/rules", json=payload)
        if resp.status_code in (200, 201):
            rule_id = resp.json().get("id", "?")
            log.info("  ✓ Rule yaradıldı: '%s' (id=%s)", name, rule_id)
            return True
        log.error("  ✗ Rule yaradılmadı '%s': HTTP %d — %s", name, resp.status_code, resp.text[:300])
        return False

    def update_rule(self, rule_id: int, aql_query: str, description: str = "") -> bool:
        """Mövcud rule-u yeniləyir."""
        payload = {
            "enabled": True,
            "notes":   description,
            "tests":   [
                {
                    "type":       "AND",
                    "name":       "AQL Filter",
                    "id":         1,
                    "uid":        "AQL_FILTER",
                    "parameters": [{"name": "Query", "value": aql_query}],
                    "group_functions": [],
                }
            ],
        }
        resp = self._request("POST", f"/analytics/rules/{rule_id}", json=payload)
        if resp.status_code in (200, 201):
            log.info("  ↺ Rule yeniləndi: id=%d", rule_id)
            return True
        log.error("  ✗ Rule yenilənmədi (id=%d): HTTP %d — %s", rule_id, resp.status_code, resp.text[:300])
        return False

    def deploy_rules(self, rules_dir: str) -> tuple[int, int, int]:
        """
        Qovluqdakı bütün Sigma rule-larını QRadar-a deploy edir.

        Returns:
            (created, updated, failed) sayları
        """
        sigma_files = glob.glob(os.path.join(rules_dir, "**", "*.yml"), recursive=True)
        sigma_files += glob.glob(os.path.join(rules_dir, "**", "*.yaml"), recursive=True)

        if not sigma_files:
            log.warning("'%s' qovluğunda heç bir Sigma faylı tapılmadı!", rules_dir)
            return 0, 0, 0

        log.info("Tapılan rule faylları: %d", len(sigma_files))
        existing = self.get_existing_rules()
        created = updated = failed = 0

        for sigma_file in sorted(sigma_files):
            log.info("İşlənir: %s", sigma_file)
            converted = sigma_to_aql(sigma_file)
            if not converted:
                failed += 1
                continue

            name  = converted["name"]
            aql   = converted["aql_query"]
            desc  = converted["description"]

            log.debug("  AQL: %s", aql)

            if name in existing:
                ok = self.update_rule(existing[name], aql, desc)
            else:
                ok = self.create_rule(name, aql, desc)

            if ok:
                if name in existing:
                    updated += 1
                else:
                    created += 1
            else:
                failed += 1

        return created, updated, failed


# ─── Giriş nöqtəsi ────────────────────────────────────────────────────────────
def main() -> None:
    log.info("=" * 60)
    log.info("QRadar Rule Deploy Skripti başladı")
    log.info("=" * 60)

    # Konfiqurasiyanı yoxla
    if not QRADAR_HOST or not QRADAR_API_TOKEN:
        log.error(
            "Mühit dəyişənləri təyin edilməyib!\n"
            "  export QRADAR_HOST='<qradar-ip>'\n"
            "  export QRADAR_API_TOKEN='<api-token>'"
        )
        sys.exit(1)

    if not os.path.isdir(RULES_DIR):
        log.error("Rules qovluğu tapılmadı: %s", RULES_DIR)
        sys.exit(1)

    client = QRadarClient(QRADAR_HOST, QRADAR_API_TOKEN)

    if not client.test_connection():
        log.error("QRadar-a qoşulmaq mümkün olmadı. Proses dayandırılır.")
        sys.exit(1)

    created, updated, failed = client.deploy_rules(RULES_DIR)

    log.info("=" * 60)
    log.info("Deploy tamamlandı:")
    log.info("  ✓ Yaradıldı : %d", created)
    log.info("  ↺ Yeniləndi : %d", updated)
    log.info("  ✗ Xəta      : %d", failed)
    log.info("=" * 60)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
