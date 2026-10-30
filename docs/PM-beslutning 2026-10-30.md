# PM-beslutning: svar på teknisk gennemgang
**Fra:** Projektleder · **Til:** Udvikler · **Dato:** 30. oktober 2026
**Vedrører:** gennemgang af MVP-koden, foreslået arkitektur og udviklingsrækkefølge
**Status:** Besluttet, undtagen de punkter der kræver ejerens beslutning (afsnit 8)

Kort fortalt: rigtig diagnose og rigtig overordnet retning, men rækkefølgen og den første leverance skal ændres. Vi bygger ikke Linux-agenten først.

---

## 1. Dine tre rettelser

**A. DNS-rebinding.** Godkendt, men nedprioriteret til P2. Du har ret i, at `resolve_public_ips()` kaldes, hvorefter resultatet kasseres, så httpx laver sit eget opslag. Det er en reel TOCTOU. Men: ekstern scanning er ikke MVP'ens primære fokus; den køres kun på eksplicit importerede domæner, ét ad gangen, af en operatør med API-nøgle. Vi retter det i uge 2 som en afgrænset opgave (1–2 dage: forbindelses-pinning via `httpx` transport med fast IP + SNI/Host samt test af begge veje), og vi udvider ikke den eksterne scanning før fase 3.

**B. Tests.** Godkendt uden forbehold, men prioriteret efter fejlrate fremfor filtype. Rækkefølge: (1) versionskomparatorer, (2) statusgitteret, (3) determinisme-hashes, (4) auth/DNS/DB. Eksterne scanner-tests er sekundære, da den eksterne scanner er et observationslag og ikke en påstandsmaskine.

**C. Dokumentationen.** Afvist — den er opdateret. README beskriver allerede `X-API-Key`, binding til `127.0.0.1:8787` og "Current limitations". Der står intet sted, at løsningen er en scaffold uden autentificering. Læs `README.md` og `INSTALL-ATHOS.md` i `main` igen, før du retter i dem. Hvis du har læst en ældre kopi fra `dk-php-scanner-mvp.zip`, er det den, der er forældet.

---

## 2. Arkitekturbeslutning: plugin først, agent bagefter — samme kontrakt

Din analyse er korrekt: `probe()` kan ikke opgraderes til en sårbarhedsscanner, og den eksterne scanner skal bevares som observationslag. Det er vedtaget.

Men jeg kan ikke gå med til, at den lokale **Linux-agent** bliver den første leverance. Begrundelse, i prioriteret rækkefølge:

1. **Køberen har ikke root-adgang.** Beslutningsnotatet peger på WordPress-bureauer med 20–100 sites som den første købergruppe. De har wp-admin, men hverken SSH eller root-adgang til kundernes hosting. En agent, der kræver root på hver host, henvender sig til en anden kundegruppe (hostingudbydere og driftsteams) og har en helt anden salgscyklus.
2. **Pluginet kan give flere svar, end du antager.** Det kører i den PHP-proces, der betjener den pågældende vhost. Derfor: `PHP_VERSION`/`PHP_VERSION_ID` er den aktive runtime for netop det site, `/var/lib/dpkg/status` og `/etc/os-release` er læsbare for alle uden root og uden `exec()`, og ved at sammenholde `PHP_VERSION` med pakkeversionen kan man se, om pakken er opdateret, men workeren ikke er genstartet. Det dækker scenarie 1, 3 og 4. Scenarie 2 (flere pools) og 5 (fjernudførelse) forbliver `undetermined` — hvilket er korrekt og acceptabelt, så længe rapporten gør det tydeligt.
3. **Kontrakten kan rumme begge dele.** Vi definerer manifestet som en liste over **runtime-observationer** pr. host fremfor som ét site-objekt. På den måde kan agenten senere sende flere pools i samme manifest, uden at datamodellen skal ændres.

**Beslutning:**
- Agent-interface og datamodel dimensioneres til host-niveau fra dag 1 (pool, proces, binærfil, pakke, `probe_status`, `probe_method`).
- Den første implementerede indsamler er WordPress-pluginnet.
- Linux-agenten er et fase 2-produkt, målrettet hostingudbydere og driftsmiljøer. Datamodellen er den samme.
- Ekstern scanning forbliver på observationslaget; ingen udvidelse før fase 3.

Det ændrer ikke på produktretningen i beslutningsnotatet. Det ændrer på, hvem vi først kan sælge til, og det er den beslutning, der betyder mest.

---

## 3. Trin 1 godkendt — med tilføjelser til evidenskontrakten

Vi starter med datamodel og evidenskontrakt. Kontrakten skal fryses i uge 1 som en versionsstyret fil i repoet (`contracts/manifest.v1.json` + dokumentation), og den skal indeholde følgende, som din skitse mangler:

| Felt | Hvorfor |
|---|---|
| `probe_status` pr. observation (`ok` / `unavailable` / `denied` / `error`) | For at skelne mellem "vi kiggede og fandt intet" og "vi fik ikke adgang" |
| `probe_method` (`constant`, `dpkg-status-file`, `os-release`, `wp-api`, `agent-syscall`) | Bevisværdien er forskellig og skal kunne revideres |
| `runtime[]` som liste, ikke enkeltobjekt | Én host kan have flere pools/versioner (scenarie 2) |
| `package_identity` inkl. `distribution`, `distribution_release`, `version_scheme` | Uden dette kan backports ikke vurderes (scenarie 4) |
| `observed_at` + `collected_at` pr. observation | Worker-data kan være ældre end selve indsamlingen |
| `agent_version`, `site_key_id`, `nonce`, `issued_at`, `signature` | Replay-beskyttelse og sporbarhed |
| `negative_observations` | "Felt utilgængeligt" skal være data, ikke et manglende felt |
| `limitations[]` | Fx `remote-fastcgi-unresolved`, `other-sapis-unknown`, `container-image-unknown` |

Ingen loginoplysninger, ingen brugernavne, ingen stier ud over PHP-binæren, ingen IP-adresser. `known_disabled_functions` er fortsat udeladt.

**Definition of done for trin 1:** kontrakten er fastlåst, der findes en gyldig og en ugyldig fixture pr. felt, og evalueringsmotoren kan læse den uden netværksforbindelse.

---

## 4. De fem scenarier er nu acceptkriterier

Godkendt som acceptkriterier for plugins/agenten. Forventet resultat skal være fastlagt på forhånd, ellers kan vi ikke teste:

| # | Scenarie | Kilde | Forventet resultat |
|---|---|---|---|
| 1 | CLI har PHP 8.3, FPM kører 8.2 | pluginets `PHP_VERSION` pr. pool + `packages[]` | Vurdering pr. runtime. Websites resultat følger FPM, ikke CLI. CLI nævnes i `limitations` |
| 2 | Flere FPM-versioner på samme host | `runtime[]` + pool-mapping | Hvert site knyttes til sin pool. Sites uden mapping: `undetermined`, aldrig `fixed` |
| 3 | Pakke opdateret, gamle workers kører | `PHP_VERSION` vs. pakkeversion | `affected` (eller `restart_required` som handlingsstatus) — aldrig `fixed` |
| 4 | Ubuntu-backport uden versionsspring | `distribution_release` + versioneret backport-mapping | `fixed` kræver verificeret mapping for netop den pakkeidentitet, ellers `undetermined` |
| 5 | PHP kører på en anden server/container | manglende/local-only evidens | `undetermined` + `limitations: remote-fastcgi-unresolved` |

Fælles regel: **ingen af de fem må udløse `fixed` eller "sikker".** Det skrives som en property-baseret test, ikke som en manuel gennemgang.

---

## 5. Revideret udviklingsrækkefølge

Din liste er korrekt i indhold, men rækkefølgen er forkert. Her er den justerede plan med v0.1's tolv uger som ramme:

| Uge | Leverance |
|---|---|
| 1 | Gate 0: B1–B5 besluttet; manifest v1 (host-kapabel) fastlåst; trusselsmodel på 3 sider |
| 1–2 | Alembic indført; skema til org/site/runtime/manifest/finding/report/audit; site-nøgler; append-only audit |
| 2 | DNS-pinning (P2-opgave) og auth-tests |
| 3–5 | **Plugin v0** (read-only, `probe_status`, Ed25519, backoff) i stedet for Linux-agent |
| 4–7 | Feeds: Wordfence Intelligence, php.net, OSV, CISA KEV + snapshot-hashes |
| 6–9 | Versionskomparatorer, evaluator som ren funktion, HTML-rapport med dækning og begrænsninger |
| 9–10 | Bureau-flow, signerede og tilbagekaldelige links, eksport |
| 11 | Hærdning og ekstern sikkerhedsgennemgang |
| 12 | Pilot hos 1–2 bureauer |
| Fase 2 | Linux-agent til Ubuntu/Debian, Apache `mod_php`, containere, andre distributioner — samme kontrakt |

Vedrørende trin 2–6: datamodellen og API'et bygges som planlagt, men den første indsamler er et plugin. Linux-agenten genbruger API'et uden ændringer, netop fordi kontrakten er host-agnostisk.

---

## 6. Syv tekniske fund, du ikke nævnte

Disse påvirker kravet om at bevare data og historik og skal medtages i uge 2:

1. **Intet migrationsværktøj.** Skemaet oprettes med `CREATE TABLE IF NOT EXISTS` ved startup. Så snart vi har tilføjet tabeller, kan vi ikke ændre skemaet uden manuel indgriben. Indfør Alembic, før der oprettes nye tabeller.
2. **`/results.csv` streamer ikke.** `fetchall()` henter hele resultatsættet, og `StreamingResponse` modtager én enkelt streng. Eksporten vil fejle ved store datasæt.
3. **CSV-formel-injektion.** `server_header` og `x_powered_by` kommer fra tredjepart. En værdi, der starter med `=`, `+`, `-` eller `@`, eksekveres i Excel. Escape værdierne eller præfiksér med `'`.
4. **Blokerende DNS i async-endpoint.** `socket.getaddrinfo()` kaldes i `probe()` på event-loopet. Én langsom resolver blokerer alle requests. Brug `loop.getaddrinfo()`, når pinning alligevel implementeres.
5. **`@app.on_event("startup")` er deprecated** i nyere FastAPI-versioner. Skift til lifespan, før der tilføjes mere startup-logik.
6. **Ingen rate limit på import.** 1000 domæner pr. request, ingen throttling og ingen audit af, hvem der har importeret hvad. Det er både en driftsmæssig og en compliance-mangel.
7. **Én statisk API-nøgle.** Ingen rotation, ingen per-tenant-nøgler og ingen logning pr. nøgle. Dette skal være på plads før pilotfasen (uge 11), ikke efter.

## 7. Bevarelse af den eksisterende database

Vedtaget. Vi sletter ikke `domains` og `scans`, og vi ændrer hverken Docker-netværk eller firewall.

Men `scans` er **eksterne observationer**, og de må ikke blandes ind i den nye evidensmodel. Konkret: `scans` fryses som legacy-tabel, den nye model får sine egne tabeller, og rapportlaget må aldrig bruge `scans` som grundlag for en `fixed`-vurdering. Hvis vi blander dem, arver vi logikken "header betyder version", hvilket er præcis den fejl, hele notatet advarer mod.

---

## 8. Kræver beslutning fra ejer før uge 1 kan lukkes

1. **B1 Distributionskanal** — egen signeret zip + eget update-endpoint, eller wordpress.org.
2. **B2 Licens til trivselsdata** — Wordfence Intelligence er gratis til kommerciel brug; WPScan og Patchstack kræver betalt licens. Skal verificeres skriftligt.
3. **B3 Datalagring og databehandlingsmodel** — EU-hosting, DPA-skabelon.
4. **B4 Tenancy** — bureau → kunde → site, og hvem der ejer et site.
5. **B5 Pilotpris og antal sites.**

B2 og B3 skal gennemgås juridisk, før der skrives kode, som sender data ud af kundens hosting. Det er ikke en formalitet: det er den beslutning, der afgør, om plugin-modulet overhovedet er lovligt at sælge.

---

## 9. De næste fem arbejdsdage

| Dag | Leverance | Ansvarlig |
|---|---|---|
| 1 | Manifest v1 som fil + fixture pr. felt; review med mig | Udvikler |
| 2 | Alembic + skemaudkast; `scans`-tabel markeres som legacy i kode og dokumentation | Udvikler |
| 3 | Trusselsmodel på 3 sider (plugin, backend, feed, rapportlinks) | Udvikler + sikkerhedsreviewer |
| 4 | Skitser til versionskomparator med property-baserede tests (Debian, RPM, WP 4-led) | Udvikler |
| 5 | Plugin-scaffolding: read-only probes med `probe_status`, ingen transport endnu | Udvikler |

Gate 0 lukkes, når ejeren har nedskrevet B1–B5, og jeg har godkendt manifestet.

---

*Opfølgning: dette er et beslutningsgrundlag, ikke en produktionsgodkendelse. Beslutningsnotatets krav til fase 0 gælder fortsat.*
