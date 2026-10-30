# B4 — Intern intern adgangs- og prospectmodel

Status: revideret designforslag. Dokumentation alene; ingen database-, API- eller produktionsændringer.

## 1. Formål og produktgrænse

PHP Exposure Scanner er et **internt arbejdsredskab for Inmente**. Det bruges af Inmentes autoriserede medarbejdere til at undersøge websites, identificere mulige PHP-sikkerheds- og vedligeholdelsesproblemer og kvalificere potentielle kunder.

Systemet er ikke et SaaS-produkt og har ingen ekstern kunde-, bureau- eller selvbetjeningsportal.

Eksterne virksomheder, webbureauer, websites og domæner er research-/prospectdata. De er ikke brugerkonti og får ikke login til scanneren.

## 2. Kanonisk arbejdsmodel

`Inmente → interne brugere → prospects → websites/domæner → scanninger → observationer/fund → lead-opfølgning`

- **Inmente** er den interne ejer og eneste organisation, der bruger systemet.
- **Intern bruger** er en medarbejder eller anden udtrykkeligt autoriseret person hos Inmente.
- **Prospect** er en virksomhed eller organisation, som Inmente undersøger som mulig kunde.
- **Website** er et identificerbart websted, der kan have flere domæner/hostnames.
- **Scanning** er en teknisk undersøgelse med tidspunkt, metode og resultat.
- **Observation/fund** er tekniske data fra scanningen. Et fund er ikke automatisk bevis for en sårbarhed.
- **Lead-opfølgning** registrerer intern vurdering, kontaktforsøg, status og næste handling.

Et webbureau kan være et prospect på samme måde som en anden virksomhed. Det får ikke en organisation i systemets adgangshierarki og får ikke delegeret adgang.

## 3. Foreslåede kernedata

### internal_user
`id UUID PK, identity_subject, display_name, email, role, status, created_at, last_seen_at nullable`

Kun interne, inviterede/autoriserede brugere. Identitet bør kobles til Inmentes valgte login-/SSO-løsning. Ingen offentlig registrering.

Roller i første version holdes enkle:
- `admin`: brugeradministration og systemkonfiguration.
- `analyst`: prospects, scanninger, vurderinger og opfølgning.
- `viewer`: læseadgang til interne rapporter.

### prospect
`id UUID PK, legal_name, organization_number nullable, website_url nullable, prospect_type, status, source, notes, created_at, updated_at`

`prospect_type` kan fx være virksomhed, webbureau eller anden organisation. Status og kontaktdata er interne salgsoplysninger. Indsaml kun nødvendige oplysninger.

### prospect_domain
`id UUID PK, prospect_id FK, hostname, relationship_type, verification_status, first_seen_at, last_seen_at, notes`

Et prospect kan have flere websites/domæner. Et domæne kan ikke uden videre antages at tilhøre en virksomhed alene på baggrund af DNS eller teknisk hosting. Ejerskab/tilknytning skal kunne stå som ukendt eller ubekræftet.

### scan_target
`id UUID PK, prospect_domain_id FK nullable, hostname, authorization_basis, status, created_at`

Mål og grundlag for, at Inmente må foretage den pågældende undersøgelse, skal kunne dokumenteres. Scanning må ikke automatisk starte alene fordi et domæne er fundet i research.

### scan
Eksisterende scan-historik bevares. Nye scanninger skal knyttes til scan_target/prospect_domain, når koblingen er kendt. Gem metode, start/slut, scanner-version, status og teknisk evidens.

### finding / observation
Tekniske observationer holdes adskilt fra vurderinger og salgsstatus. En HTTP-observation må ikke fremstilles som bekræftet sårbarhed uden tilstrækkelig evidens. `undetermined` skal være en gyldig konklusion.

### lead_activity
`id UUID PK, prospect_id FK, actor_user_id FK, activity_type, occurred_at, summary, next_action nullable, next_action_at nullable`

Registrerer intern kvalificering, kontaktforsøg, møder, afvisninger og opfølgning. Undgå at gemme unødvendige personoplysninger eller følsomt indhold.

### audit_event
`id UUID PK, actor_user_id FK, action, target_type, target_id, occurred_at, metadata JSONB`

Auditér login-/rolleændringer, scanninger, eksport, ændringer af autorisationsgrundlag og ændringer i lead-status. Metadata må ikke indeholde credentials eller hemmeligheder.

## 4. Adgangsregler

1. Kun Inmentes autoriserede interne brugere kan logge ind.
2. Ingen kunde-, prospect- eller bureau-login.
3. Ingen invitationsflow for eksterne brugere og ingen delegerede eksterne grants.
4. Alle adgangskontroller håndhæves server-side efter intern rolle.
5. Eksport, rapporter og baggrundsjob følger samme interne adgangspolitik.
6. Scanninger kræver dokumenteret og passende autorisationsgrundlag; intern adgang er ikke i sig selv tilladelse til at scanne et tredjeparts website.
7. Logning må ikke eksponere API-nøgler, tokens eller andre hemmeligheder.

## 5. Historik og datalivscyklus

- Eksisterende `domains` og `scans` skal bevares; ingen destruktiv migration som del af designarbejdet.
- Historiske scanninger må ikke få en prospect-tilknytning gættet. Ukendt relation forbliver ukendt, indtil den er verificeret.
- Observationer, tekniske vurderinger og lead-status er separate begreber.
- Prospect- og kontaktdata skal have formål, adgangsbegrænsning og slette-/retentionsregler.
- B3's databeskyttelsesbeslutninger skal afklares før behandling af personoplysninger i pilot. Dette dokument fastsætter ikke endelig retention eller juridisk rollefordeling.
- Alle tider gemmes UTC.

## 6. Ikke omfattet

- Kundeportal, kundelogin eller bureau-login.
- Ekstern selvbetjening, invitationer eller delegeret adgang.
- Kommerciel multi-tenant SaaS-arkitektur.
- SQL-migration, API-ændring eller applikationskode.
- Ændringer på Athos eller automatisk scanning af uopfordrede tredjepartsdomæner.

Dette PR er alene et revideret designforslag.

## 7. Implementeringsrækkefølge

1. Godkend Inmente som eneste interne brugerorganisation og fastlæg interne roller.
2. Afklar login/SSO og brugeradministration for Inmentes medarbejdere.
3. Fastlæg prospect-statusser, lead-workflow og nødvendige kontaktfelter.
4. Fastlæg dokumentation af autorisationsgrundlag før scanning.
5. Design migrationsmapping fra eksisterende `domains` og `scans`, uden at gætte ejerskab.
6. Implementér interne adgangskontroller og negative tests.
7. Tilføj prospect- og lead-funktioner i UI/API efter separat godkendelse.

## 8. Acceptkriterier for B4

- Kun autoriserede Inmente-brugere kan logge ind.
- Interne roller håndhæves server-side.
- Ingen eksterne brugeridentiteter eller kunde-/bureau-login findes i modellen.
- Prospects kan have flere domæner/websites.
- Domæne-/virksomhedstilknytning kan være ubekræftet.
- Scanninger har dokumenteret autorisationsgrundlag.
- Historiske scanninger bevares og tilknyttes ikke prospects ved gæt.
- Tekniske fund og lead-status er adskilte.
- Lead-opfølgning kan spores til intern bruger og tidspunkt.
- Audit dækker adgang, scanning og eksport.
