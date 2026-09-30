# MMENC2 – Sicherheits- und Formatentwurf

**Status:** Entwurf zur Architekturentscheidung  
**Bezug:** MMProtect Repository `MMProtect-OpenSource/MMProtect`, Stand des ausgecheckten `main`-Branches am 30.09.2026  
**Ziel:** Die im MMENC1-Format vorhandenen Austausch-, Header-, Schlüssel- und Replay-Angriffsflächen reduzieren und die Extraktion erschweren. MMENC2 kann keinen Klartextschutz gegen einen Angreifer garantieren, der den PHP-Prozess oder das Betriebssystem kontrolliert.

## 1. Sicherheitsziel und Grenze

MMENC2 soll Vertraulichkeit und Manipulationserkennung für jede geschützte Datei liefern, alle sicherheitsrelevanten Metadaten kryptografisch binden und die Folgen eines extrahierten Schlüssels auf eine Datei bzw. eine kurze Laufzeit begrenzen. Der Loader gibt den PHP-Quelltext letztlich an Zend weiter. Ein Angreifer mit Administratorrechten kann Debugger, veränderte PHP-Binary, manipulierte Extension oder Speicherzugriff nutzen. Ziel ist deshalb **Widerstandserhöhung und Begrenzung des Schadens**, keine absolute Unangreifbarkeit.

Bedrohungen, die MMENC2 adressiert:

- Austausch einer verschlüsselten Datei zwischen Pfaden, Projekten, Kunden, Builds oder Lizenzen.
- Manipulation von Header, Kompressionsoptionen, Serveradresse, Manifestbezug oder Lease-Antwort.
- Wiederverwendung abgefangener Leases oder Schlüsselantworten auf einem anderen Rechner bzw. für andere Dateien.
- Extraktion eines einzelnen Dateischlüssels: Er soll keine anderen Dateien entschlüsseln.
- Parserfehler, Integer-Überläufe, übergroße Header und Dekompressionsbomben.

Nicht vollständig adressierbar: Root/Admin auf dem Zielsystem, Patchen des Loaders/PHP, beliebiges Dumpen von entschlüsseltem Quelltext oder Opcodes, kompromittierter Lizenzserver/Encoder sowie Schlüsselmissbrauch durch einen autorisierten Betreiber.

## 2. Konkrete MMENC1-Befunde im Repository

Die Befunde beziehen sich auf `src/EncoderCli/Encoding/MmencContainer.cs`, `CryptoPrimitives.cs`, `ProjectEncoder.cs`, `src/PhpDecoderLoader/mmloader.c` und `src/LicenseServer/Security/CryptoService.cs`:

1. Der Encoder erstellt einen zufälligen `buildKey`, leitet alle Dateischlüssel daraus ab und der Lease liefert `runtimeKey` (den Build-Key) an den Loader. Eine Extraktion betrifft damit den gesamten Build.
2. Die Datei-ECDSA-Signatur deckt nur `buildId:fileId:cipherHash` ab. Sie bindet weder Nonce/Tag noch Pfad, Hashes, Kompression, Manifest, IDs oder Lizenzserveradresse.
3. Die AES-GCM-Verschlüsselung verwendet kein AAD. Der Tag schützt daher allein die Chiffretextdaten.
4. Ohne ECDSA-Key existiert im Encoder ein SHA-256-Dateisignaturfallback. Ein Hash ist keine Signatur. Release-Pfade sollten ihn nicht akzeptieren.
5. `pathHash` und `fileId` werden vom Container gelesen; die Loaderprüfung muss sie gegen den tatsächlich aufgelösten Pfad und das authentische Manifest binden.
6. Der Lease-Signaturtext lässt laut Doku einen Maschinen-Fingerprint einfließen, die Antwortstruktur und Prüfung müssen aber ausdrücklich sicherstellen, dass genau der lokal erwartete Fingerprint signiert und verglichen wird.
7. Das optionale `licenseServer`-Headerfeld ist derzeit nicht signiert. Ein Angreifer kann so die Autorisierungsanfrage umlenken.
8. MMENC1 verwendet ASCII-Längenfeld und JSON/cJSON. Größenlimit ist im Loader vorhanden, aber doppelte JSON-Schlüssel, kanonische Serialisierung und numerische Grenzfälle sind über Implementierungen hinweg fehleranfällig.
9. Das Signieren des Headers vor dem endgültigen `manifestHash` (Platzhalter-/Zweitpass) erschwert eine konsistente, vollständige Signaturbindung.

## 3. Kryptografische Suite für MMENC2

MMENC2 startet mit einer einzigen obligatorischen Suite, ohne algorithmische Aushandlung aus untrusted Headerdaten:

| Verwendung | Festlegung |
|---|---|
| Dateiverschlüsselung | AES-256-GCM, 32-Byte DEK, 12-Byte Nonce, 16-Byte Tag |
| Dateischlüssel | Zufälliger 32-Byte-DEK pro geschützter Datei und Build; kein aus Build-Key abgeleiteter gemeinsamer Schlüssel |
| Hash | SHA-256 |
| Schlüsselumschlag am Server | AES-256-GCM unter KEK aus Secret Manager/HSM; AAD bindet Tenant, Build, File-ID und Key-ID |
| Laufzeit-Schlüsselübergabe | Ephemeres ECDH über NIST P-256, HKDF-SHA256, AES-256-GCM; Antwort mit separater Server-ECDSA-P256-Signatur |
| Datei-/Manifest-Signaturen des Vendors | ECDSA-P256/SHA-256, rohe feste 64-Byte `r || s`-Kodierung (P1363); keine Fallback-Signaturen |
| Lease-/Key-Envelope-Signaturen des Servers | eigener ECDSA-P256/SHA-256-Schlüssel mit eigener `keyId` und getrenntem Trust-Store-Eintrag; keine Wiederverwendung des Datei-Signaturschlüssels |
| Container-Kodierung | Deterministisches CBOR nach RFC 8949 für Header/Signaturpayload; keine JSON-Mehrdeutigkeit |

Die IDs in kryptografischen Kontexten sind UTF-8-Bytes mit Längenpräfixen oder deterministisches CBOR. Nicht `a + ":" + b` ohne Längen-/Kodierungsschutz verwenden. Alle Domain-Strings enthalten ein abschließendes NUL-Byte, z. B. `MMProtect/MMENC2/file-key\0`.

## 4. MMENC2 Dateicontainer

Alle Ganzzahlen in der äußeren Hülle sind unsigned, Big Endian. Das deterministische CBOR-Headerobjekt ist höchstens 64 KiB. Implementierungen müssen die Headerlänge, Dateilänge und alle Additionen vor Allokation/Pointer-Arithmetik prüfen.

```text
Offset  Größe            Inhalt
0       8                ASCII `MMENC2\r\n`
8       4                Headerlänge (uint32 BE), 1..65536
12      Headerlänge      Deterministisches CBOR: geschützte Metadaten
12+H    C                AES-256-GCM-Chiffretext (Länge aus Dateiende minus Trailer)
...     16               GCM-Tag
...     64               ECDSA-P256-Signatur (P1363 r||s)
```

Kein Padding. Dateiende muss exakt auf den Trailer fallen. Mindestlänge, maximale PHP-Dateigröße und `ciphertextLength == plaintextOrCompressedLength` sind zu validieren.

### 4.1 Headerfelder

CBOR-Map mit integer keys, damit Schlüsselreihenfolge und Namen nicht variieren. Unbekannte kritische Keys führen zur Ablehnung; optionale Extensions liegen in einem explizit namespaced Feld und dürfen keine Parser-/Sicherheitsentscheidung überschreiben.

| Key | Feld | Inhalt / Validierung |
|---:|---|---|
| 1 | `format` | Text `MMENC2` |
| 2 | `version` | unsigned integer `2` |
| 3 | `suite` | integer `1` = oben festgelegte Suite |
| 4 | `projectId` | opake, längenbegrenzte ID |
| 5 | `customerId` | opake, längenbegrenzte ID |
| 6 | `licenseId` | opake, längenbegrenzte ID |
| 7 | `buildId` | opake, längenbegrenzte ID |
| 8 | `fileId` | zufällige 16-Byte-ID je Build-Datei, ausschließlich als CBOR-ByteString kodiert |
| 9 | `relativePath` | normalisierter relativer UTF-8-Pfad, `/`, ohne NUL, `.`/`..`, absolute oder doppelte Separatoren |
| 10 | `pathHash` | 32 Byte SHA-256 des normalisierten Pfades |
| 11 | `plainHash` | 32 Byte SHA-256 des finalen PHP-Klartexts nach Optimierung/Obfuskierung, vor Kompression |
| 12 | `keyId` | ID des serverseitig gespeicherten DEK-Datensatzes |
| 13 | `manifestId` | zufällige, vorab erzeugte ID des Builds/Manifests; kein Hash |
| 14 | `createdAt` | Unix-Zeit als integer; keine freie Datumsstring-Interpretation |
| 15 | `compression` | integer `0` = keine, `1` = LZ4-Block; weitere Werte ablehnen |
| 16 | `plainLength` | unkomprimierte Länge, begrenzt per Loaderkonfiguration |
| 17 | `payloadLength` | Chiffretextlänge; muss zur Outer-Containerlänge passen |
| 18 | `nonce` | 12 zufällige Bytes; pro DEK niemals wiederverwenden |

`algorithm`, `kdf`, `signature`, `tag`, `cipherHash` und `licenseServer` werden nicht als frei aushandelbare Headerwerte verwendet. Suite und Kodierung sind versionsfest. Der Serverendpunkt kommt aus signierter Loaderkonfiguration bzw. lokaler INI-Allowlist, nie aus einer untrusted Datei.

### 4.2 AAD und Signatur

- `AAD = UTF8("MMProtect/MMENC2/AAD\\0") || exactHeaderBytes`.
- Der Encoder verschlüsselt erst, nachdem das vollständige Headerobjekt erstellt wurde. `payloadLength` und Nonce stehen somit bereits fest. Länge ist vor Kompression bekannt.
- Tag steht im festen Trailer, nicht im Header. Chiffretext-Hash ist im Manifest und wird vor Lease-Anfrage geprüft.
- Dateisignaturpayload: `UTF8("MMProtect/MMENC2/file-signature\\0") || uint32be(headerLength) || exactHeaderBytes || SHA256(ciphertext) || tag`.
- ECDSA-Signatur wird über SHA-256 dieses Payloads erstellt. Verifikation erfolgt vor Netzwerkzugriff; GCM-Authentifizierung erfolgt vor Dekompression/Compilation.
- Signatur bindet Headerbytes exakt. Der Loader akzeptiert kein nichtdeterministisches CBOR, keine doppelte Map-Keys und keine nicht-minimalen Integer-Kodierungen.

Die GCM-AAD bindet alle Headerfelder, die vor Verschlüsselung bekannt sind. Signatur und Manifest binden zusätzlich den Chiffretext-Hash und Tag. Kein Feld wie Pfad oder Kompression darf ungebunden bleiben. **Der Container enthält keinen `manifestHash`:** Sonst entstünde ein Hash-Kreis, wenn das Manifest den Ciphertext-Hash enthält, dieser Ciphertext von AAD abhängt und die AAD wiederum den Manifesthash enthält. Stattdessen bindet `manifestId` den Container an die vorab erzeugte Manifestidentität; das signierte Manifest listet danach den Hash des vollständigen Containers und Ciphertexts. Der Loader nimmt den Manifesthash aus dem verifizierten Manifest bzw. der Serverregistrierung und sendet ihn im Lease-/Key-Request.

## 5. Schlüsselmodell ohne auslieferbaren Build-Key

### 5.1 Encoder und Server

1. `POST /api/v2/encoder/builds/start` erzeugt nur eine Build-ID und `keyId`-Namensräume. Es gibt keinen Build-Key zurück.
2. Für jede Datei erzeugt der Encoder mit CSPRNG einen unabhängigen 32-Byte-DEK.
3. Der Encoder sendet den DEK über authentifiziertes TLS an einen Encoder-Endpunkt. Der Lizenzserver verschlüsselt ihn mit KEK/HSM unter AAD `tenantId, projectId, buildId, fileId, keyId`; die DB speichert nur den umhüllten DEK.
4. Encoder verschlüsselt Datei lokal, löscht DEK/Klartextbuffer bestmöglich und sendet File-Metadaten, Header, CipherHash und Signatur zur Buildregistrierung.
5. Encoder erzeugt vorab eine zufällige `manifestId`, die in alle Dateiheader kommt. Er verschlüsselt und signiert alle Dateien, berechnet danach die endgültigen Container- und Ciphertext-Hashes, baut das Manifest und signiert es. Der Server committet Build und Manifest atomar. Damit gibt es keinen Hash-Kreis und keine `pending`-Werte im signierten Output.

Der Encoder-Signing-Key signiert Dateicontainer und Manifest. Der API-Key des Encoders darf nur Builds innerhalb zugewiesener Projekte anlegen/registrieren und niemals Vendor-Signing-Key-Material abrufen.

### 5.2 Maschinengebundene, kurzlebige Schlüsselantwort

1. Loader hält ein signiertes Manifest und validiert `fileId`, Pfad, `pathHash`, `plainHash`, `cipherHash`, `buildId`, `licenseId` und `manifestId`. Den Manifesthash selbst bezieht er aus dem verifizierten Manifest.
2. Für eine Laufzeitsitzung erzeugt er in RAM ein ephemeres P-256-Schlüsselpaar und eine zufällige 32-Byte-Session-ID. Private Bytes nur bis Laufzeitende halten und explizit nullen.
3. Loader fordert mit `fileId`, `buildId`, `manifestHash`, `machineFingerprint`, Session-ID, monotonic/nonce challenge und ephemeral public key eine Dateischlüssel-Autorisierung an.
4. Server prüft Lizenz, Build/File-Status, Maschine, Limits und Revocation. Er lädt den DEK aus der Datenbank und erzeugt ein ephemeres P-256-Schlüsselpaar.
5. Beide Seiten leiten `sharedSecret = ECDH(P-256)` ab. `wrapKey = HKDF-SHA256(sharedSecret, salt=SHA256(sessionId || requestNonce), info=CBOR(["MMProtect/MMENC2/key-wrap", projectId, buildId, fileId, keyId, machineFingerprint]), L=32)`.
6. Server liefert `serverEphemeralPublicKey`, zufälligen Wrap-Nonce, verschlüsselten 32-Byte-DEK, GCM-Tag, Session-ID, Request-Nonce, File-ID, Manifesthash, `issuedAt`, `expiresAt`, Lizenzstatus und `keyId`. Diese vollständige Antwort wird mit Vendor ECDSA-P256 signiert.
7. Loader verifiziert Signatur, IDs, lokal erwarteten Fingerprint, Challenge, Session-ID und knappe Ablaufzeit (z. B. maximal 5 Minuten), leitet Wrap-Key ab und entschlüsselt den DEK. AAD für den Schlüsselumschlag sind dieselben Bindungsfelder.
8. Pro Datei wird nur der DEK dieser Datei freigegeben. Loader cached DEKs ausschließlich in Prozessspeicher für höchstens die Laufzeitsitzung/kurze TTL. Keine Build-Keys und keine unverschlüsselten DEKs auf Disk.

Eine optionale Batch-API darf z. B. maximal 16 konkrete File-IDs pro Anfrage umhüllen, muss jede File-ID einzeln in den signierten Antworten binden und dieselbe Machine-/Sessionbindung anwenden. Keine pauschale Freigabe eines ganzen Build-Keys.

### 5.3 Offlinebetrieb

Der sichere Standard ist Online-Autorisierung pro Datei und kein Offline-Grace. Falls Offlinebetrieb Produktanforderung ist, als klar getrennten Modus umsetzen:

- Registrierung eines Geräte-Schlüssels auf Betriebssystem-Key-Store/TPM (DPAPI/Windows CNG, Linux TPM2 oder Secret-Service mit dokumentiertem Softwareschlüssel-Fallback).
- Server signiert kurzlebige, maschinen- und manifestgebundene Offline-Key-Envelopes. Umschlag-DEKs mit dem registrierten Geräte-Public-Key; maximaler Offlinezeitraum ist Lizenzpolitik.
- Software-Fallback ist gegen lokale Administratoren nicht geheim; UI/Doku kennzeichnet reduzierte Sicherheit.
- Widerruf wirkt erst nach Ablauf/Onlinekontakt. Kein Text darf behaupten, gecachte Schlüssel seien auf kontrolliertem Host sicher löschbar.

## 6. Manifest v2

- Deterministisches CBOR oder exakt definierte Canonical-JSON-Implementierung; Empfehlung: deterministisches CBOR wie beim Header.
- Manifest enthält alle geschützten Dateien mit `fileId`, normalisiertem `relativePath`, `pathHash`, `plainHash`, `cipherHash`, `containerHash` (SHA-256 über komplette MMENC2-Datei), `payloadLength`, `keyId`, Kompression und Suite.
- Manifest enthält Projekt-, Kunden-, Lizenz-, Build-IDs, `manifestVersion=2`, Encoder-Version, Erstellzeit und Signatur-Key-ID.
- `manifestHash = SHA256(exact canonical manifest payload with hash/signature fields omitted)`.
- Vendor-Signatur über domain-separated Manifestpayload und Hash; keine Signatur eines losgelösten Hashstrings ohne Domain Separation.
- Loader berechnet den tatsächlichen relativen Pfad aus dem geladenen Pfad relativ zum konfigurierten Projektroot und vergleicht Manifest/Container exakt. Symlink-/Case-fold-Regeln sind plattformübergreifend festzulegen.
- Manifest darf nicht aus einem neben der Datei liegenden, frei austauschbaren Pfad als vertrauenswürdig gelten: Signatur und Serverregistrierung sind Pflicht.

## 7. Runtime-Lease v2 und Anti-Replay

Lease autorisiert Projekt-/Build-/Maschinenstatus, enthält aber keinen Schlüssel. Datei-DEKs laufen über den separaten File-Key-Endpunkt.

Lease- und Key-Envelope-Signaturen umfassen mindestens: Protokollversion, Server-Key-ID, zufällige Antwort-ID, Client-Nonce, Loader-Session-ID, project/customer/license/build/file IDs (bei File-Key), Manifesthash, Fingerprint, `issuedAt`, `expiresAt`, zulässige Features und Policy-Version. Alle Felder sind Teil des kanonischen Signaturpayloads. Server signiert auch Fehler-/Deny-Antworten optional, damit Offline-/Replay-Interpretation eindeutig bleibt.

- Nonces werden serverseitig für ein begrenztes Zeitfenster gegen Replay geprüft; Zeitfenster/Rate Limits dokumentieren.
- Maschinen-Fingerprint allein ist kein Hardware-Sicherheitsanker. Er ist ein Lizenzmerkmal, kein Geheimnis.
- TLS-Zertifikatsprüfung bleibt obligatorisch; keine `CURLOPT_SSL_VERIFYPEER=0`- oder Hostname-Bypasses.
- Antwortgrößen, Connect-/Total-Timeout und JSON/CBOR-Limits strikt setzen.
- Lizenzserver-DNS/URL kommt aus lokaler signierter Konfiguration/Allowlist; keine Redirects zu beliebigen Hosts, keine private/link-local URL-Umleitung.

## 8. Loader-Anforderungen

1. **Fail closed:** Release-Build startet nicht ohne vertrauenswürdigen Vendor-Public-Key. Keine Hash-/HMAC-/Dev-Fallbacks im Release.
2. Containerformat anhand Magic erkennen. MMENC2 nicht als MMENC1 interpretieren. MMENC1 bleibt nur in separat konfiguriertem Legacy-Pfad aktiv.
3. Feste Maximalwerte für Header, Datei, Pfad, Manifest, Antwort und Dekompression. Alle Integer-/Pointerüberläufe und Trunkierungen ablehnen.
4. Signature/Manifest/Pfad/Build/Lizenz/Key-ID prüfen, bevor Netzwerkaufruf oder große Allokation geschieht.
5. Erst nach erfolgreicher Schlüsselumschlagprüfung GCM finalisieren. Keine teilweise entschlüsselten Bytes an Zend weiterreichen.
6. Erst nach erfolgreicher GCM-Authentifizierung dekomprimieren. LZ4-Ausgabegröße exakt `plainLength`, Obergrenze konfiguriert, Verhältnis begrenzt; `LZ4_decompress_safe`-Rückgabewert exakt prüfen.
7. Pfadnormalisierung ohne Locale-Abhängigkeit. Pfad traversal, NUL, absolute Pfade, symlink escape und unerwartete Case-Kollisionen ablehnen.
8. DEK, ECDH-Secret, Wrap-Key, Zwischenpuffer und Klartext bestmöglich explizit nullen; alle Fehlerpfade und longjmp/Zend-Fehlerpfade abdecken. `explicit_bzero`/OpenSSL cleanse nur dort nutzen, wo der Compiler die Löschung nicht wegoptimiert.
9. PHP-/OPcache-Guards bleiben defense-in-depth. Sie verhindern nicht das Auslesen bereits entschlüsselter Opcodes aus einem manipulierten Host.
10. Keine sensiblen Inhalte in Logs/Telemetrie: kein Schlüssel, Nonce+Ciphertext-Paket, Klartext, privater Pfad oder vollständiger Fingerprint.

## 9. Änderungen an den vorhandenen Projektkomponenten

### Encoder CLI (`src/EncoderCli`)

- Neue Typen `Mmenc2Container`, `Mmenc2Header`, `Mmenc2Manifest`, deterministic-CBOR-Codec, `FileKeyClient`.
- `MmencContainer.Create`/`CryptoPrimitives.HkdfSha256` nicht für MMENC2 wiederverwenden; kein Build-Key und keine HKDF-Ableitung von Dateischlüsseln aus einem gemeinsamen Root.
- `ProjectEncoder` in zweiphasigen Build umbauen: `manifestId` vorab erzeugen; Container vollständig schreiben/signieren; dann Manifest über endgültige Containerhashes bauen und signieren.
- 32-Byte-DEK je Datei separat per OS-CSPRNG erzeugen, Upload an geschützten Server-Endpunkt, nach Verwendung löschen.
- Private Signaturkey-Pflicht; Build bricht bei fehlendem Schlüssel ab. Public Key mit `keyId`/Rotation provisionieren.
- `--format mmenc1|mmenc2` nur während Übergang. Neue Builds standardmäßig MMENC2; kein stiller Rückfall.

### Lizenzserver (`src/LicenseServer`)

- Schema für `file_keys` mit unique `(build_id,file_id,key_id)`, KEK-umschlag, Status und Rotation.
- KEK aus Secret Manager/HSM, kein Demo- oder Klartextkey in Produktion. KEK-ID pro Version speichern, Rotation/Rewrap definieren.
- v2 Build API ohne `buildKey`; Endpunkte für Upload/Commit und file-scoped key envelope.
- Atomare Prüfung von Lizenz, Kunde, Build, Datei, Manifest, Aktivierung, Constraints, Widerruf und Rate-Limit.
- Signierte, domain-separated Key-Envelope-/Lease-Antworten; Signaturkey-IDs für Rotation.
- Audit-Events nur Metadaten und abgekürzte IDs.

### Zend Loader (`src/PhpDecoderLoader`)

- Parser für die äußere v2-Hülle und deterministisches CBOR (mit harten Limits und Fuzzing).
- Trust store mit mindestens aktivem/überlappendem Signatur-Public-Key für Rotation.
- Neue v2 Signatur-/Manifestvalidierung, tatsächliche Pfadbindung, Challenge und ECDH-Key-Envelope.
- Entfernen von Build-Key aus RAM/Leasecache; bestehende MMENC1-Funktionen isolieren und standardmäßig optional abschalten.
- Alle PHP-ABIs und Linux/Windows-Builds für OpenSSL-ECDH/Signaturgleichheit testen.

## 10. Migration und Rückwärtskompatibilität

- MMENC1 und MMENC2 sind unterschiedliche Container-Magics und getrennte Parser.
- Loader-Konfiguration: `mmloader.allowed_formats = mmenc2` als Zielzustand; Übergang `mmenc1,mmenc2` nur für bekannte Altbestände.
- Encoder kann v1-Dateien nicht in-place „hochversionieren“ ohne Klartext/Neuverschlüsselung. Quelldateien erneut mit MMENC2 encodieren.
- MMENC1-Builds/Leases widerrufen oder mit Ablaufdatum versehen, wenn ein v1-Key bekannt geworden ist.
- Rolloutfolge: Lizenzserver v2 Tabellen/API → Loader mit MMENC2 (noch keine Builds erforderlich) → Encoder v2 → Testbuilds → Projekte neu encodieren → MMENC1 im Kundensystem deaktivieren.
- Bei Schlüsselrotation mindestens zwei Vendor Public Keys über eine signierte Updatekette unterstützen; private Signierschlüssel getrennt von Encoder-Host aufbewahren.

## 11. Test- und Abnahmekriterien

### Kompatibilität und Roundtrip

- C# Encoder erzeugt Container, C Loader liest/prüft/entschlüsselt; Testvektoren für deterministisches CBOR, AAD, AES-GCM, ECDH, HKDF und ECDSA P1363 sind sprachübergreifend identisch.
- PHP 8.4/8.5, FPM/CLI und OPcache; Linux und Windows Loader-Builds.
- Unkomprimiert und LZ4; Unicode-Pfade nach festgelegter Normalisierung; leere/kleine/grenzgroße Dateien.

### Negative/Security-Tests

- Jedes Headerbyte einzeln manipulieren; falscher Tag/Signatur/Manifest/Hash/Pfad/Build/Lizenz/File-ID/Key-ID.
- Ciphertext zwischen Dateien, Builds, Projekten und Kunden austauschen.
- Doppelte CBOR-Keys, nicht-kanonische Kodierung, unbekannte kritische Felder, überlange/unterlange/trunkierte Daten, Integer-Overflow, ungültige P-256-Public-Keys und Signaturgrößen.
- Kompressionsbomben, `plainLength` mismatch, Null-/Riesenlänge, negative LZ4-Rückgabe.
- Replay der Lease/Key-Antwort, falsche Maschine, falsche Client-Nonce, abgelaufene Antwort, widerrufener Build/Lizenz.
- Lizenzserver URL Redirect/SSRF, TLS-Zertifikatsfehler, übergroße/abgebrochene Antwort.
- Fuzzing für Containerparser, CBOR, Manifest, Key-Envelope und Kompressionsheader mit ASan/UBSan auf C-Seite.
- Speicherbereinigung auf allen Fehlerpfaden prüfen; Tests bestätigen keine Klartextdatei auf Disk.

### Sicherheitsabnahme

MMENC2 gilt erst als implementierungsreif, wenn unabhängige Review die Kryptografie-/Protokollparameter, Serverautorisierung, Key-Wrapping, Containergrenzen und C-Fehlerpfade geprüft hat. Ein eigener Algorithmus oder eine behauptete Root-Sicherheit ist kein Abnahmekriterium.

## 12. Offene Architekturentscheidungen vor Implementierung

1. Ist Onlinezugriff pro erstmals geladener Datei akzeptabel, oder ist Offlinebetrieb eine harte Anforderung?
2. Soll der Server DEKs in einer DB-HSM/Secret-Manager-Integration verwalten, oder sollen DEKs beim Encoder erzeugt und nur KEK-verschlüsselt hochgeladen werden? Empfehlung: Encoder erzeugt DEK; Server speichert nur KEK-verschlüsselten DEK.
3. Welche maximale PHP-Dateigröße und LZ4-Ausgabegröße sollen Loader und Server durchsetzen?
4. Welche Pfadnormalisierung soll für Windows/Linux gelten (Unicode NFC, Case-sensitivity, Symlinks)?
5. Welche Laufzeit-TTL für File-Key-Envelopes ist mit FPM-Worker-Lebenszyklus und Performance vereinbar?
6. Wie werden Vendor-Signaturkeys publiziert/rotiert und Kunden-Loader aktualisiert?

## 13. Empfohlene Reihenfolge

1. Protokollparameter und Pfadkanonisierung fixieren; unabhängige Security-Review.
2. Testvektoren/Referenz-Codec erstellen, bevor C# oder C Loader angepasst werden.
3. Lizenzserver-Key-Speicher und v2 API umsetzen (kein Build-Key-Endpunkt in v2).
4. Encoder MMENC2 + Manifest v2 + zwei Phasen implementieren.
5. Loader Parser/Security Gates/Key Envelope integrieren; Fuzzing zuerst für Parser.
6. End-to-End-/Cross-Language-/OPcache-/Offlinepolicy-Tests abschließen.
7. MMENC2 auf Testlizenz ausrollen, Laufzeit- und Fehlertelemetrie ohne Geheimnisse prüfen, anschließend Bestandsprojekte neu encodieren.
