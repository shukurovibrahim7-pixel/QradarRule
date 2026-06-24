#!/usr/bin/env python3
"""
add_offense_close_reasons.py
============================
QRadar-da "Custom Offense Close Reason" parametrlərini əlavə edən skript.
Task 15 - True-Positive və False-Positive close reason-larını yaradır.

Defolt olaraq QRadar 3 close reason-la gəlir:
  1. Non-Issue
  2. Policy Violation
  3. True-Positive  ← Bu skript əlavə edir
  4. False-Positive ← Bu skript əlavə edir
  (və istənilən başqa özel parametrlər)

İstifadə:
    python3 add_offense_close_reasons.py

Mühit dəyişənləri:
    QRADAR_HOST       - QRadar IP/hostname
    QRADAR_API_TOKEN  - QRadar SEC API Token
"""

import os
import sys
import time
import logging
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── Konfiqurasiya ─────────────────────────────────────────────────────────────
QRADAR_HOST      = os.environ.get("51.21.74.45", "")
QRADAR_API_TOKEN = os.environ.get("e8465730-610a-4290-ad3a-86fb9b117caf", "")
API_VERSION      = "17.0"
TIMEOUT          = 30

# Əlavə ediləcək Close Reason-lar
# "text" — interfeysdə görünəcək ad
# "reserved" — True = dəyişdirilə bilməz (standart), False = custom
CLOSE_REASONS_TO_ADD: list[dict] = [
    {
        "text":        "True-Positive",
        "description": "Həqiqi hücum/insidentdir. Müvafiq cavab tədbirləri görülmüşdür.",
        "reserved":    False,
    },
    {
        "text":        "False-Positive",
        "description": "Yanlış alarm. Rule və ya threshold tənzimlənməlidir.",
        "reserved":    False,
    },
    {
        "text":        "Benign Activity",
        "description": "Normal fəaliyyətdir, hücum deyil. Whitelist-ə əlavə edilməlidir.",
        "reserved":    False,
    },
    {
        "text":        "Under Investigation",
        "description": "Araşdırma davam edir. Müvəqqəti olaraq bağlanır.",
        "reserved":    False,
    },
    {
        "text":        "Duplicate Offense",
        "description": "Eyni hadisə üçün başqa offense açıqdır.",
        "reserved":    False,
    },
]


class QRadarOffenseManager:
    """QRadar Offense idarəetmə API-si ilə işləyən sinif."""

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

    def _get(self, endpoint: str) -> requests.Response:
        return requests.get(
            f"{self.base_url}{endpoint}",
            headers=self.headers,
            verify=False,
            timeout=TIMEOUT,
        )

    def _post(self, endpoint: str, data: dict) -> requests.Response:
        return requests.post(
            f"{self.base_url}{endpoint}",
            headers=self.headers,
            json=data,
            verify=False,
            timeout=TIMEOUT,
        )

    def get_existing_close_reasons(self) -> dict[str, int]:
        """
        Mövcud close reason-ların {text: id} xəritəsini qaytarır.
        Endpoint: GET /siem/offense_closing_reasons
        """
        resp = self._get("/siem/offense_closing_reasons")
        if resp.status_code != 200:
            log.error("Close reason-lar alınmadı: HTTP %d — %s", resp.status_code, resp.text[:200])
            return {}
        existing = {r["text"]: r["id"] for r in resp.json()}
        log.info("Mövcud close reason sayı: %d", len(existing))
        for name, rid in existing.items():
            log.info("  [id=%d] %s", rid, name)
        return existing

    def add_close_reason(self, text: str, description: str = "") -> bool:
        """
        Yeni close reason yaradır.
        Endpoint: POST /siem/offense_closing_reasons
        """
        payload = {
            "text":     text,
            "reserved": False,
        }
        resp = self._post("/siem/offense_closing_reasons", payload)
        if resp.status_code in (200, 201):
            new_id = resp.json().get("id", "?")
            log.info("  ✓ Əlavə edildi: '%s' (id=%s)", text, new_id)
            return True
        elif resp.status_code == 409:
            log.info("  ℹ Artıq mövcuddur: '%s'", text)
            return True
        else:
            log.error("  ✗ Əlavə edilmədi '%s': HTTP %d — %s",
                      text, resp.status_code, resp.text[:300])
            return False

    def setup_close_reasons(self) -> tuple[int, int]:
        """
        Bütün lazımi close reason-ları əlavə edir.

        Returns:
            (added, skipped) sayları
        """
        existing = self.get_existing_close_reasons()
        added = skipped = 0

        log.info("\nYeni close reason-lar əlavə edilir...")
        for reason in CLOSE_REASONS_TO_ADD:
            name = reason["text"]
            if name in existing:
                log.info("  ℹ Mövcuddur, keçilir: '%s'", name)
                skipped += 1
                continue

            ok = self.add_close_reason(name, reason.get("description", ""))
            if ok:
                added += 1
                time.sleep(0.5)   # Rate limit üçün qısa fasilə
            else:
                log.warning("  ✗ Əlavə edilmədi: '%s'", name)

        return added, skipped

    def close_offense_with_reason(self, offense_id: int, reason_text: str) -> bool:
        """
        Müəyyən bir offense-i seçilmiş close reason ilə bağlayır.
        (Test/demo məqsədi ilə)

        Endpoint: POST /siem/offenses/{offense_id}
        """
        existing = self.get_existing_close_reasons()
        if reason_text not in existing:
            log.error("Close reason tapılmadı: '%s'", reason_text)
            return False

        reason_id = existing[reason_text]
        payload   = {
            "status":                  "CLOSED",
            "closing_reason_id":       reason_id,
            "closing_reason_username": "blue-team-automation",
        }
        resp = self._post(f"/siem/offenses/{offense_id}", payload)
        if resp.status_code in (200, 201):
            log.info("Offense #%d '%s' ilə bağlandı", offense_id, reason_text)
            return True
        log.error("Offense #%d bağlanmadı: HTTP %d — %s",
                  offense_id, resp.status_code, resp.text[:200])
        return False


# ─── Giriş nöqtəsi ────────────────────────────────────────────────────────────
def main() -> None:
    log.info("=" * 55)
    log.info("QRadar Custom Offense Close Reason Skripti")
    log.info("=" * 55)

    if not QRADAR_HOST or not QRADAR_API_TOKEN:
        log.error(
            "Mühit dəyişənləri təyin edilməyib!\n"
            "  export QRADAR_HOST='<qradar-ip>'\n"
            "  export QRADAR_API_TOKEN='<api-token>'"
        )
        sys.exit(1)

    manager = QRadarOffenseManager(QRADAR_HOST, QRADAR_API_TOKEN)

    # Bağlantını yoxla
    try:
        resp = requests.get(
            f"https://{QRADAR_HOST}/api/system/about",
            headers={"SEC": QRADAR_API_TOKEN, "Version": API_VERSION},
            verify=False, timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            log.error("QRadar bağlantısı uğursuz: HTTP %d", resp.status_code)
            sys.exit(1)
        log.info("QRadar bağlantısı uğurlu ✓ (v%s)", resp.json().get("release_name", "?"))
    except Exception as exc:
        log.error("Bağlantı xətası: %s", exc)
        sys.exit(1)

    # Close reason-ları əlavə et
    added, skipped = manager.setup_close_reasons()

    log.info("\n" + "=" * 55)
    log.info("Nəticə:")
    log.info("  ✓ Yeni əlavə edildi : %d", added)
    log.info("  ℹ Artıq mövcud idi  : %d", skipped)
    log.info("=" * 55)
    log.info(
        "\nQRadar Admin panelindən yoxlamaq üçün:\n"
        "  Admin → System Configuration → Custom Offense Close Reasons"
    )


if __name__ == "__main__":
    main()
