# bunny-guard

Sperrt Port 443 (oder andere Ports) für alle außer BunnyCDN. Wer die Server-IP kennt,
kommt nicht mehr direkt an die Seiten, nur noch über Bunny.

- holt die offizielle Bunny-Edge-Liste (IPv4 + IPv6) per curl und hält sie aktuell
- filtert mit einer eigenen nftables-Tabelle, UFW/firewalld/Docker bleiben unangetastet
- TCP und UDP (HTTP/3) werden gefiltert, Docker-Ports per DNAT ebenfalls
- interaktiver Assistent: erkennt deine Domains, prüft DNS, fragt nach Ausnahmen
- Domains, die **ohne** Bunny erreichbar sein sollen, lassen sich gezielt freigeben
- testet nach dem Aktivieren alles und setzt automatisch zurück, wenn du nicht bestätigst

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/zerox80/bunny-UFW.sh/main/bunny-guard.sh -o bunny-guard.sh
sudo bash bunny-guard.sh
```

Der Assistent installiert sich nach `/usr/local/sbin/bunny-guard`. Danach reicht `sudo bunny-guard`.

Voraussetzungen: Linux mit systemd und nftables-fähigem Kernel, z.B. Debian 11+,
Ubuntu 22.04+, RHEL/Alma/Rocky 9+. Fehlende Pakete (`nftables`, `curl`, …) bietet der
Assistent zur Installation an. Ob Kernel und nft alle benötigten Funktionen können, testet
er vorher mit einer Probe-Tabelle. In OpenVZ/LXC-Containern ohne nftables bricht er
deshalb sauber ab.

## Ablauf des Assistenten

1. Voraussetzungen und nftables-Funktionen prüfen
2. Bunny-Listen laden und auf Plausibilität prüfen
3. IP-Adressen des Servers anzeigen
4. Ports wählen (Standard: 443). SSH-Ports werden abgelehnt, damit du dich nicht aussperrst
5. Domains aus nginx, Apache, Caddy und Let's-Encrypt-Zertifikaten auflisten, mit DNS-Einschätzung
   (*über Bunny*, *direkt auf diesen Server*, *anderer Server*). Hier wählst du die Domains,
   die ohne Bunny erreichbar sein sollen. Mehrere gehen mit Leerzeichen oder Komma
   (`2 3`, `2,3`), Bereiche mit `2-4`, alle mit `alle`. Nicht gelistete Domains tippst du
   einfach ein
6. Weitere Ausnahmen: private Netze (Docker, VPN, LAN), eigene IPs
7. Abgleich mit UFW/firewalld und Zusammenfassung
8. Aktivieren, testen, bestätigen

Bis Schritt 8 wird an der Firewall nichts geändert. Nach dem Aktivieren läuft ein Timer:
Bestätigst du nicht innerhalb von 5 Minuten, wird alles auf den vorherigen Stand
zurückgesetzt. Das gilt auch, wenn die SSH-Verbindung abbricht.

## Domains ohne Bunny

Eine Firewall sieht nur IP und Port, keine Domain. Deshalb prüft das Tool, wie sich eine
Ausnahme umsetzen lässt:

- **Domain liegt auf einer eigenen IP:** Diese IP wird für alle geöffnet. Vorher testet
  das Tool, ob der Webserver auf dieser IP auch Bunny-Seiten ausliefert. Ist das so,
  fragt es nach.
- **Domain teilt sich die IP mit Bunny-Seiten** (der Normalfall bei einer einzigen IPv4):
  - *nginx-Modus*: Die IP wird geöffnet und nginx sperrt alle anderen server-Blöcke für
    Nicht-Bunny-Besucher (`return 444`). Die nötige `include`-Zeile fügt das Tool nach
    Rückfrage selbst ein, mit Backup und `nginx -t`. Schlägt der Test fehl, wird die
    Änderung zurückgenommen.
  - IP trotzdem komplett öffnen. Dann ist der Bunny-Schutz auf dieser IP aus.
  - Überspringen. Die Domain bleibt gesperrt.

Der nginx-Modus ist schwächer als die reine Firewall: Wer die IP scannt, sieht noch das
TLS-Zertifikat. Am saubersten ist eine zweite IP für die direkten Dienste.

## Befehle

| Befehl | Zweck |
|---|---|
| `sudo bunny-guard` | Assistent (einrichten oder ändern) |
| `sudo bunny-guard status` | Zustand, Listen, Paketzähler |
| `sudo bunny-guard check` | alle Tests, `--extern` testet zusätzlich von außen |
| `sudo bunny-guard update [--force]` | Bunny-Liste sofort aktualisieren |
| `sudo bunny-guard reload` | Konfiguration nach Handänderung neu laden |
| `sudo bunny-guard disable [--yes]` | Schutz abschalten, Konfiguration bleibt |
| `sudo bunny-guard enable` | wieder einschalten |
| `sudo bunny-guard rollback` | letzte Einrichtung zurücknehmen |
| `sudo bunny-guard cleanup-ufw [--apply]` | alte UFW-Regeln mit BunnyCDN-/Gcore-Kommentar entfernen |
| `sudo bunny-guard uninstall [--yes]` | alles entfernen |

## Prüfen, ob es wirklich funktioniert

`sudo bunny-guard check` prüft:

- ob die Tabelle geladen ist, ob die Bunny-IPs im Kernel stehen, Alter der Liste, Timer
- **Ende-zu-Ende über Bunny:** Anfrage an deine Domain mit Cache-Buster. Bunny meldet
  über `CDN-RequestPullSuccess`, ob es den Server erreicht hat
- ob Bunny-Seiten über freigegebene IPs direkt erreichbar sind
- ob die Domains ohne Bunny noch auf die freigegebene IP zeigen
- mit `--extern`: TCP-Test von mehreren Standorten über check-host.net. Dabei wird die
  Server-IP an check-host.net übermittelt, deshalb fragt das Tool vorher.

Selbst testen von einem anderen Rechner (PowerShell). Das muss fehlschlagen:

```powershell
Test-NetConnection DEINE.SERVER.IP -Port 443
```

`sudo bunny-guard status` zeigt die Zähler: wie viele Pakete von Bunny kamen und wie viele
verworfen wurden.

## Wie es funktioniert

- Tabelle `inet bunny_guard` mit Hooks `input` und `forward` (Priorität -10, also vor
  UFW, firewalld und Docker). Auf den geschützten Ports wird verworfen, was nicht von
  Bunny, einer erlaubten Quelle oder an eine freigegebene Ziel-IP geht. Docker-Ports
  werden über den ursprünglichen Zielport (`ct original proto-dst`) erkannt.
- Regeln werden atomar ersetzt. Beim Aktualisieren gibt es keinen Moment, in dem der
  Port offen ist.
- `bunny-guard.service` lädt die Regeln beim Booten aus dem Cache, noch bevor das Netz
  hochkommt. Wird `nftables.service` neu gestartet, lädt sich bunny-guard danach mit.
- `bunny-guard-update.timer` läuft alle 10 Minuten. Er stellt die Tabelle wieder her,
  falls jemand `nft flush ruleset` ausgeführt hat, und lädt alle 6 Stunden die
  Bunny-Liste neu.
- Eine neue Liste wird nur übernommen, wenn alle Einträge gültige IPs sind und sie nicht
  auf weniger als die Hälfte schrumpft. Sonst bleibt die alte Liste aktiv (erzwingen:
  `update --force`).
- Ist UFW aktiv und lässt 443 nur für einzelne IPs zu, bietet das Tool `ufw allow 443/tcp`
  an. Das passiert erst, wenn der Bunny-Filter bereits läuft.

## Dateien

| Pfad | Inhalt |
|---|---|
| `/etc/bunny-guard/bunny-guard.conf` | Einstellungen (Ports, Ausnahmen, Test-Domains) |
| `/var/lib/bunny-guard/` | Bunny-Listen, letzter Regelsatz, nginx-Backups |
| `/etc/nginx/conf.d/bunny-guard-geo.conf` | nur im nginx-Modus: Bunny-Liste für nginx |
| `/etc/nginx/snippets/bunny-guard-only.conf` | nur im nginx-Modus: die Sperre |

Logs: `journalctl -u bunny-guard -u bunny-guard-update`

## Hinweise

- **Port 80:** Wird er mit gesperrt, schlagen Let's-Encrypt-Prüfungen per HTTP-01 fehl.
  Der Assistent warnt davor.
- **Alte UFW-Regeln:** Regeln mit Kommentar `BunnyCDN`/`Gcore` werden nach der
  Einrichtung zum Entfernen angeboten, mit Backup unter `/root/ufw-cdn-backup-*`.
  Regeln ohne Kommentar werden nie automatisch gelöscht.
- Der externe Test prüft nur IPv4. IPv6 bitte von Hand testen.

## Lizenz

MIT
