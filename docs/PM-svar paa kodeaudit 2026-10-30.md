# PM-svar på kodeaudit
**Fra:** Projektleder · **Til:** Udvikler · **Dato:** 30. oktober 2026
**Vedrører:** kodeaudit af commit `11f8f5e`, udført 30. oktober 2026
**Status:** Auditten godkendes som arbejdsgrundlag. Seks fund ændrer rækkefølgen. To præciseres.

---

## 1. Afgørelse

Auditten er saglig, og den korrigerer sig selv på det punkt, hvor den tidligere gennemgang tog fejl: autentificering findes i GitHub-versionen. Det bekræfter min afvisning af dokumentationspunktet fra i går — README var ajour, og det var ZIP-filen, der var forældet.

**Vi stopper her:** `probe()` udvides ikke til patchvurdering. Auditten og beslutningsnotatet siger det samme, og det er nu låst.

Jeg har efterprøvet to af audittens påstande uafhængigt og kan bekræfte dem:

- Teksten `Article: upgrading to PHP 8.3.6` matcher versionregexen og giver `version-disclosed`. Fund A7 er ægte.
- `https://example.com:8443/` og `https://example.com:notaport/` normaliseres begge til `example.com` uden fejl. Porten forsvinder lydløst, og `:notaport` accepteres, fordi `urlparse().hostname` ikke validerer porten.

---

## 2. Triage

Prioritet: **P1** = blokerer al videre udvikling, **P2** = før bredere adgang, **P3** = før pilot.

| ID | Fund | Prioritet | Handling | Uge |
|---|---|---|---|---|
| A6 | Image og commit ikke entydigt bundet | **P1** | `build:` i compose, commit-SHA i `/health` og i OCI-label, digest ved publicering | 1 |
| A7 | HTML-tekst læses som PHP-version | **P1** | `evidence_source` + `observation_type` i manifest v1; regex kun på headers | 1 |
| A8 | `confidence` blander fejl og evidens | **P1** | `probe_status` + `error_code`; `scans` fryses som legacy | 1 |
| A9 | Ingen tests, intet reproducerbart build | **P1** | CI fra første commit; fixtures pr. felt | 1 |
| A1 | DNS-binding mangler | P2 | Fast IP i transport + SNI/Host bevaret; test begge veje | 2 |
| A4 | CSV-formelinjektion + `fetchall()` | P2 | Escapes, batch-eksport, rå JSON ved siden af | 2 |
| A5 | Applikationen bruger bootstrap-kontoen | P2 | Tre roller: bootstrap, migration, applikation. Undersøg eksisterende volume først | 2 |
| A2 | Ingen samlet deadline, blokerende I/O | P3 | Jobdeadline + concurrency-grænse; worker i fase 3 | 3–5 |
| A3 | `MAX_RESPONSE_BYTES` ikke hård grænse | P3 | Græns både rå og dekodede bytes; registrér afkortning | 3–5 |
| — | Porte fortiet, IP-literal accepteret som domæne | P2 | Afvis eksplicit port og IP-literal; `8.8.8.8` accepteres i dag som domæne | 2 |

**Ændring i forhold til audittens rækkefølge:** A7 og A8 ligger i auditten sidst (punkt 6). Jeg flytter dem til uge 1, fordi de er identiske med de felter, der allerede skulle fryses i manifest v1. At lave dem som en senere opgave ville betyde, at kontrakten blev skrevet to gange.

---

## 3. To præciseringer til auditten

**A6 forklarer sandsynligvis driftsproblemet, men ikke som auditten antyder.** `docker compose up -d --build` bygger ikke denne service, fordi `compose.yml` ikke har en `build:`-sektion. På en vært med et eksisterende lokalt image startes gammel kode; på en ny vært fejler opstarten. Det betyder, at den kode, der kører på athos, ikke med sikkerhed er `11f8f5e`. **Ingen konklusion om timeouten på athos kan bruges, før det er afklaret.** Det er derfor A6 er P1 og ikke "driftsmæssigt væsentlig".

**Advarsel mod den oplagte rettelse af A1.** Hvis nogen sætter `internal: true` på `scanner_internal` for at lukke egress, kan API-containeren ikke nå internettet, og så fejler alle scanninger. Netværksisolation og scanning er i direkte konflikt i denne arkitektur. Egress skal styres med en allow-list eller en dedikeret proxy, ikke ved at gøre netværket internt. Det skal stå i trusselsmodellen, før nogen "retter" det.

---

## 4. Fund auditten ikke dækkede

| # | Fund | Konsekvens |
|---|---|---|
| N1 | Skemaet oprettes med `CREATE TABLE IF NOT EXISTS`; ingen migrationsværktøj | Første skemaændring kræver manuel indgriben på produktionsdata |
| N2 | `final_url` er ikke final — redirects følges ikke, feltet er altid den forsøgte URL | Rapporten kan påstå en URL, der aldrig blev hentet |
| N3 | `probe()` forsøger HTTPS og derefter HTTP; begge fejl lægges i `notes`, afkortet til 1000 tegn | Man kan ikke se, hvilket forsøg der fejlede, eller om HTTP blev forsøgt |
| N4 | `import_domains` rapporterer `accepted_or_existing` | Nye og allerede importerede domæner kan ikke skelnes; ingen audit af hvem der importerede |
| N5 | `q` i `/domains` sendes til `ILIKE` med `%` og `_` aktive | Ikke SQL-injektion, men søgemønstre kan manipuleres |
| N6 | Ingen rate limit, ingen scan-budget, ingen concurrency-grænse | 1000 domæner kan scannes i én kø uden loft |
| N7 | Ingen auditlog pr. API-nøgle; én statisk nøgle | Skal være på plads før pilot (uge 11) |
| N8 | `php_indicator` er en boolsk blanding af header- og tekstfund | Samme fejl som A7, blot som flag |

---

## 5. Revideret rækkefølge for de første fem dage

| Dag | Leverance |
|---|---|
| 1 | `build:` i compose, commit-SHA i `/health`, CI-workflow der kører på PR. Fastlæg hvilken commit der kører på athos |
| 2 | Manifest v1 med `evidence_source`, `observation_type`, `probe_status`, `error_code`; fixture pr. felt |
| 3 | A7/A8 indbygget i probe: regex kun på headers, `probe_status` i stedet for `confidence`; `confidence` bevares som legacy-kolonne |
| 4 | Porte og IP-literaler afvises; tests for normalisering, auth og fejlklassifikation |
| 5 | Alembic indført; `scans` markeret legacy i kode og dokumentation; trusselsmodel med egress-afsnittet |

Gate 0 lukkes fortsat af B1–B5. Auditten ændrer ikke på det, men A6 viser, hvorfor beslutningerne skal skrives ned og ikke bare aftales.

---

*Auditten er ikke en produktionsgodkendelse. Beslutningsnotatets fase 0-krav gælder fortsat.*
