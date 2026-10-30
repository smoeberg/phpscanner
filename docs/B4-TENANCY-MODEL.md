# B4 — Tenancy- og adgangsmodel

Status: designforslag. Ingen database- eller produktionsændringer.

## 1. Kanonisk model

`organization → customer → site → runtime → pool`

Relationen er ikke et simpelt træ:
- En organisation repræsenterer fx et bureau.
- En customer er kundens forretningsmæssige konto under organisationen.
- Et site er kundens stabile website-identitet, uafhængig af domæne og hosting.
- En runtime er et PHP-eksekveringsmiljø.
- En pool er en PHP-FPM-pool eller tilsvarende eksekveringsgruppe.
- Et site kan have flere domæner og flere samtidige runtime-/pool-bindinger. En pool kan betjene flere sites.

## 2. Kernetabeller

### organization
`id UUID PK, name, status, created_at, updated_at`

### customer
`id UUID PK, organization_id FK, name, external_reference nullable, status, created_at, updated_at`

En kunde tilhører én organisation i første version. Ekstern bureauadgang gives via grants, ikke ved at kopiere kunden.

### site
`id UUID PK, customer_id FK, display_name, status, created_at, updated_at, deleted_at nullable`

Site-ID er stabilt. Domæne- eller hostingændringer må ikke skabe en ny identitet eller flytte historikken til et andet site.

### site_domain
`id UUID PK, site_id FK, hostname, verification_status, verified_at, created_at`

Et site kan have flere domæner. Aktivering kræver DNS TXT- eller HTTPS `/.well-known/`-challenge. Unik aktiv hostname-binding håndhæves transaktionelt.

### site_key
`id UUID PK, site_id FK, key_id, secret_hash/public_key, created_at, expires_at, revoked_at, last_used_at nullable`

Rå hemmeligheder må ikke kunne læses fra databasen. Nøgler skal kunne roteres og tilbagekaldes. Site-binding og agentidentitet er separate forhold.

### runtime
`id UUID PK, runtime_kind, host_fingerprint nullable, php_binary nullable, package_identity nullable, first_seen_at, last_seen_at, status`

Runtime er et miljøobjekt, ikke en antagelse om at alle sites på samme host bruger samme PHP-version.

### pool
`id UUID PK, runtime_id FK, pool_identifier, created_at, retired_at nullable`

### site_runtime_binding
`id UUID PK, site_id FK, runtime_id FK, pool_id FK nullable, valid_from, valid_until nullable, linkage_status, evidence_ref nullable`

Bindinger er tidsafgrænsede. Flere samtidige bindings er tilladt ved load balancing. Historik lukkes med `valid_until` og overskrives ikke.

### access_grant
`id UUID PK, organization_id FK, customer_id FK nullable, site_id FK nullable, grantee_type, grantee_id, role, valid_from, valid_until nullable, revoked_at nullable, granted_by, created_at`

Hvert grant skal have præcis ét scope: organisation, kunde eller site. Roller: `owner`, `admin`, `operator`, `viewer`.

### audit_event
`id UUID PK, actor_type, actor_id, action, target_type, target_id, occurred_at, metadata JSONB`

Metadata må ikke indeholde credentials eller hemmeligheder. Auditér grants, domain proof, nøglelivscyklus, ændringer og rapporteksport.

## 3. Adgangsregler

1. Kunden ejer sit site. Bureauets adgang er delegeret og kan tilbagekaldes.
2. En organisation ser kun egne kunder/sites og sites med en eksplicit aktiv grant.
3. En kunde ser kun egne sites og kan administrere delegeret bureauadgang efter den valgte bruger-/rollemodel.
4. `owner` administrerer site og grants; `admin` konfiguration; `operator` scanninger; `viewer` rapporter.
5. Alle checks håndhæves server-side. Klientleverede ID'er er aldrig autorisation.
6. Servicekonti og agentnøgler har eksplicit, begrænset scope.
7. Rapport-, eksport- og baggrundsjob bruger samme adgangspolitik som almindelige API-læsninger.
8. Tilbagekaldelse og udløb blokerer straks nye handlinger.

## 4. Historik og datalivscyklus

- Observationer, vurderinger og rapporter knyttes til stabilt site-ID.
- Domæneændring opdaterer site_domain, ikke site-identiteten.
- Bureauændring opdaterer grants, ikke ejerskab eller historik.
- Runtime-/poolrelationer gemmes med gyldighedsperioder og evidens.
- Ukendt site-runtime-kæde forbliver `undetermined`.
- Sletning følger B3's vedtagne opbevaringsregler; denne model fastlægger ikke retention.
- Historiske objekter slettes ikke ved cascade som standard. Brug kontrolleret lifecycle og auditspor.

## 5. Integritet og indekser

- Foreign keys på alle relationer; `ON DELETE RESTRICT` som standard for historiske objekter.
- Indeks på customer.organization_id, site.customer_id, site_domain.hostname, site_runtime_binding.site_id/runtime_id og access_grant principal/scope.
- Alle tider gemmes UTC.
- UUID er identifikator, ikke adgangstoken.
- Constraints skal forhindre ugyldige grants og dublerede aktive domænebindings.

## 6. Ikke omfattet

Ingen SQL-migration, API-ændring, login-/invitation-flow eller ændring af eksisterende domains/scans. Ingen ændringer på Athos. Dette er alene design.

## 7. Implementeringsrækkefølge

1. Godkend begreber, ejerskab og adgangsregler.
2. Fastlæg bruger- og serviceprincipal-modellen.
3. Skriv PostgreSQL-migrationer og constraints.
4. Implementér central authorization service og negative tests.
5. Migrér domains til site/site_domain med eksplicit mapping; bevar scan-historik.
6. Eksponér først derefter tenancy i API/UI.

## 8. Acceptkriterier for B4

- Kunde kan eje flere sites.
- Site kan have flere domæner og flere samtidige runtime-/poolbindings.
- Runtimehistorik kan bevares.
- Bureau kan kun se sites med aktiv grant.
- Tilbagekaldt/udløbet grant blokerer også rapport og eksport.
- Kundens skift af bureau bevarer site-ID og historik.
- Site-ID alene giver aldrig adgang.
- Negative tests dækker cross-organization, cross-customer, revoked grant, expired grant og service-token scope.

## Åbent pilotvalg

Skal kunden have egen login-/brugeridentitet fra første pilot, eller administreres adgang i piloten alene gennem bureauet? Modellen understøtter begge dele, men invitationsflow og brugeroplevelse afhænger af beslutningen.
