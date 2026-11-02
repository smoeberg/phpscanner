from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/", include_in_schema=False, response_class=HTMLResponse)
def operator_home():
    return HTMLResponse(OPERATOR_HTML)


OPERATOR_HTML = r"""<!doctype html>
<html lang="da">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>PHP Exposure Scanner · Operator</title>
<style>
:root{font-family:system-ui,-apple-system,sans-serif;color:#17202a;background:#f4f6f8}
body{max-width:1100px;margin:0 auto;padding:24px}
header,.panel{background:#fff;border:1px solid #dce2e8;border-radius:10px;padding:18px;margin-bottom:16px}
h1{font-size:1.5rem;margin:0 0 6px}h2{font-size:1.1rem;margin:0 0 12px}
p{color:#52606d}.muted{font-size:.9rem;color:#64748b}
label{display:block;font-weight:600;margin:8px 0 4px}
input,textarea,select,button{font:inherit;padding:9px;border:1px solid #b8c3ce;border-radius:6px;max-width:100%}
input,textarea,select{width:100%;box-sizing:border-box}
textarea{min-height:70px}
button{background:#173b5e;color:white;border:0;cursor:pointer;margin:5px 4px 5px 0}
button.secondary{background:#e8edf2;color:#17202a}button.danger{background:#9b2c2c}
button:disabled{opacity:.5;cursor:wait}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.row{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.row>*{flex:1}
table{border-collapse:collapse;width:100%;font-size:.94rem}th,td{text-align:left;padding:9px;border-bottom:1px solid #e5e9ed;vertical-align:top}
td button{font-size:.85rem}.status{padding:10px;background:#eef3f7;border-radius:6px;margin:10px 0;white-space:pre-wrap}
.hidden{display:none}.tag{font-size:.8rem;background:#edf1f5;padding:3px 6px;border-radius:4px}
#key{max-width:440px}code{overflow-wrap:anywhere}
@media(max-width:650px){body{padding:12px}table{display:block;overflow-x:auto}}
</style>
</head>
<body>
<header>
<h1>PHP Exposure Scanner</h1>
<p class="muted">Intern operatørvisning · scanning kræver både DNS-verifikation og gyldig, dokumenteret tilladelse.</p>
<label for="key">API-nøgle</label>
<div class="row"><input id="key" type="password" autocomplete="off" placeholder="Indtast SCANNER_API_KEY"><button id="connect">Forbind</button></div>
<p class="muted">Nøglen bruges kun i denne browsersession og gemmes ikke i browserlageret.</p>
<div id="message" class="status" role="status">Indtast API-nøglen for at hente data.</div>
</header>

<section class="panel">
<h2>Prospects</h2>
<div class="grid">
<form id="prospect-form">
<label for="prospect-name">Navn</label><input id="prospect-name" required maxlength="200">
<label for="prospect-number">Organisationsnummer (valgfrit)</label><input id="prospect-number" maxlength="100">
<label for="prospect-website">Website (valgfrit)</label><input id="prospect-website" maxlength="500">
<label for="prospect-notes">Noter</label><textarea id="prospect-notes" maxlength="2000"></textarea>
<button>Opret prospect</button>
</form>
<form id="domain-form">
<label for="domain-import-input">Importer domæner (ét pr. linje)</label><textarea id="domain-import-input" placeholder="example.com&#10;www.example.org" required></textarea>
<button>Importer domæner</button>
<p class="muted">Import og tilknytning giver ikke tilladelse til scanning.</p>
</form>
</div>
<div class="row">
<div><label for="associate-prospect">Prospect-ID</label><input id="associate-prospect" type="number" min="1"></div>
<div><label for="associate-domain">Domæne-ID</label><input id="associate-domain" type="number" min="1"></div>
<button id="associate">Tilknyt domæne</button>
</div>
<div class="row"><div><label for="list-search">Søg i prospects og domæner</label><input id="list-search" type="search" maxlength="253" placeholder="Navn, organisationsnummer eller domæne"></div><button class="secondary" id="search-lists">Søg</button><button class="secondary" id="refresh">Opdater oversigt</button></div>
<div id="prospects"></div>
</section>

<section class="panel">
<h2>Domæner og scanning</h2>
<p class="muted">DNS TXT-verifikation dokumenterer domænekontrol, ikke scanningstilladelse. Opret først et separat autorisationsgrundlag med dokumentationsreference.</p>
<div id="domain-list"></div>
</section>

<section class="panel">
<h2>Seneste scanninger</h2>
<p class="muted">Viser de seneste registrerede HTTP-observationer. En PHP-indikation er ikke i sig selv dokumentation for en sårbarhed.</p>
<div id="scan-results"><p class="muted">Forbind for at hente scanneresultater.</p></div>
<div class="row" id="scan-pagination">
<button class="secondary" id="scan-prev" disabled>Nyere scanninger</button>
<span id="scan-page" class="muted">Side 1</span>
<button class="secondary" id="scan-next" disabled>Ældre scanninger</button>
</div>
<div id="scan-detail" class="status hidden" aria-live="polite"></div>
</section>

<section class="panel">
<h2>Autorisation</h2>
<p class="muted">Vælg et domæne-ID og registrer den konkrete tilladelse. Sørg for, at evidencereferencen peger på den faktiske aftale eller skriftlige tilladelse.</p>
<form id="authorization-form">
<div class="grid">
<div><label for="auth-domain">Domæne-ID</label><input id="auth-domain" type="number" min="1" required></div>
<div><label for="auth-type">Grundlag</label><select id="auth-type"><option value="written_permission">Skriftlig tilladelse</option><option value="contract">Kontrakt</option><option value="other">Andet</option></select></div>
<div><label for="auth-grantor">Givet af</label><input id="auth-grantor" required maxlength="200"></div>
<div><label for="auth-evidence">Evidencereference</label><input id="auth-evidence" required maxlength="1000"></div>
<div><label for="auth-from">Gyldig fra (lokal tid)</label><input id="auth-from" type="datetime-local" required></div>
<div><label for="auth-until">Gyldig til (valgfrit)</label><input id="auth-until" type="datetime-local"></div>
</div>
<label for="auth-description">Beskrivelse (valgfrit)</label><textarea id="auth-description" maxlength="2000"></textarea>
<button>Registrer autorisation</button>
</form>
<div id="authorizations"></div>
</section>

<section class="panel">
<h2>CSV-eksport</h2>
<p class="muted">Hent scanneresultater, fund og prospect-tilknytninger som CSV til videre behandling hos Sales.</p>
<button id="export-csv">Download CSV</button>
</section>

<script>
(() => {
  let apiKey = "";
  let scanOffset = 0;
  const scanPageSize = 100;
  const $ = (id) => document.getElementById(id);
  const listSearch = () => {
    const query = $("list-search").value.trim();
    return query ? "?q=" + encodeURIComponent(query) : "";
  };
  const message = (text) => { $("message").textContent = text; };
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  };
  async function api(path, options = {}) {
    if (!apiKey) throw new Error("Indtast API-nøglen og forbind først.");
    const response = await fetch(path, {
      ...options,
      headers: {"X-API-Key": apiKey, ...(options.headers || {}),
        ...(options.body ? {"Content-Type":"application/json"} : {})}
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || ("HTTP " + response.status));
    return data;
  }
  function table(headers, rows) {
    const t = el("table"), head = el("tr");
    headers.forEach(h => head.append(el("th", h)));
    const thead = el("thead"); thead.append(head); t.append(thead);
    const body = el("tbody");
    rows.forEach(row => { const tr=el("tr"); row.forEach(cell => {const td=el("td"); if(cell instanceof Node) td.append(cell); else td.textContent=cell ?? "—"; tr.append(td);}); body.append(tr); });
    t.append(body); return t;
  }
  async function refresh() {
    try {
      const [prospects, domains, scans] = await Promise.all([
        api("/prospects" + listSearch()), api("/domains" + listSearch()), api("/results?limit=" + (scanPageSize + 1) + "&offset=" + scanOffset)
      ]);
      const pRows = prospects.map(p => [
        p.id, p.name, p.organization_number || "—",
        p.domains.map(d => d.domain + " (" + d.association_status + ")").join(", ") || "Ingen domæner"
      ]);
      $("prospects").replaceChildren(table(["ID","Prospect","Org.nr.","Tilknyttede domæner"], pRows));
      const dRows = await Promise.all(domains.map(async d => {
        const authorizations = await api("/domains/" + d.id + "/authorizations");
        const currentlyAuthorized = authorizations.some(a => a.currently_authorized);
        const actions = el("div");
        const challenge = el("button","Opret DNS-challenge"); challenge.className="secondary";
        challenge.addEventListener("click", async () => {
          try { const c=await api("/domains/"+d.id+"/verification-challenge",{method:"POST"}); message("Tilføj denne TXT-record hos domæneejeren:\n"+c.record_name+"\n"+c.record_value+"\nUdløber: "+c.expires_at); }
          catch(e){message(e.message);}
        });
        const verify = el("button","Kontrollér DNS"); verify.className="secondary";
        verify.addEventListener("click", async () => {try{await api("/domains/"+d.id+"/verify",{method:"POST"});message("DNS-verifikation gennemført.");await refresh();}catch(e){message(e.message);}});
        const auth = el("button","Vis autorisation"); auth.className="secondary";
        auth.addEventListener("click", async () => { $("auth-domain").value=d.id; await loadAuthorizations(d.id); });
        const scan = el("button","Start scanning");
        scan.disabled = !d.verified || !currentlyAuthorized;
        scan.title = !d.verified
          ? "Domænet skal DNS-verificeres først."
          : (!currentlyAuthorized ? "Der mangler en gyldig og aktiv scanningstilladelse." : "");
        scan.addEventListener("click", async () => {
          try { const job=await api("/domains/"+d.id+"/scan",{method:"POST"}); message("Scan-job oprettet: "+job.job_id+" (queued)."); pollJob(job.job_id); }
          catch(e){message(e.message);}
        });
        actions.append(challenge,verify,auth,scan);
        return [
          d.id, d.domain,
          d.verified ? "Verificeret" : "Ikke verificeret",
          currentlyAuthorized ? "Gyldig tilladelse" : "Ingen gyldig tilladelse",
          actions
        ];
      }));
      $("domain-list").replaceChildren(table(["ID","Domæne","DNS-status","Scanningstilladelse","Handlinger"],dRows));
      const hasMoreScans = scans.length > scanPageSize;
      const visibleScans = scans.slice(0, scanPageSize);
      const scanRows = visibleScans.map(scan => {
        const actions = el("div");
        const details = el("button","Vis detaljer");
        details.className = "secondary";
        details.addEventListener("click", () => loadScanDetails(scan.scan_id));
        actions.append(details);
        return [
          scan.scanned_at ? new Date(scan.scanned_at).toLocaleString() : "—",
          scan.domain,
          scan.status_code ?? "Intet HTTP-svar",
          scan.php_indicator ? "Observeret" : "Ikke observeret",
          scan.version_observed || "Ikke oplyst",
          scan.confidence,
          scan.notes || "—",
          actions
        ];
      });
      $("scan-results").replaceChildren(
        scanRows.length ? table(["Tidspunkt","Domæne","HTTP-status","PHP-indikation","Observeret version","Vurdering","Noter","Detaljer"],scanRows)
          : el("p",scanOffset ? "Ingen flere scanninger på denne side." : "Ingen scanninger er registreret endnu.","muted")
      );
      $("scan-prev").disabled = scanOffset === 0;
      $("scan-next").disabled = !hasMoreScans;
      $("scan-page").textContent = "Side " + (Math.floor(scanOffset / scanPageSize) + 1);
      message("Data opdateret. "+prospects.length+" prospects, "+domains.length+" domæner og "+visibleScans.length+" scanninger hentet.");
    } catch(e) { message(e.message); }
  }
  async function loadScanDetails(scanId) {
    const panel = $("scan-detail");
    panel.classList.remove("hidden");
    panel.textContent = "Henter fund og observationer for scan #" + scanId + "…";
    try {
      const [findings, observations] = await Promise.all([
        api("/scans/" + scanId + "/findings"),
        api("/scans/" + scanId + "/observations")
      ]);
      const heading = el("h3","Scan #" + scanId + " · Fund");
      const findingRows = findings.map(f => [
        f.finding_type, f.assessment, f.confidence,
        f.version_observed || "Ikke oplyst", f.rationale || "—",
        f.evidence ? JSON.stringify(f.evidence) : "—"
      ]);
      const findingTable = findingRows.length
        ? table(["Type","Vurdering","Sikkerhed","Version","Begrundelse","Evidens"],findingRows)
        : el("p","Ingen afledte fund for denne scanning.","muted");
      const observationHeading = el("h3","HTTP-observationer");
      const observationRows = observations.map(o => [
        o.observation_type, o.value ?? "—", o.source || "—",
        o.observed_at ? new Date(o.observed_at).toLocaleString() : "—"
      ]);
      const observationTable = observationRows.length
        ? table(["Type","Observeret værdi","Kilde","Tidspunkt"],observationRows)
        : el("p","Ingen strukturerede observationer for denne scanning.","muted");
      panel.replaceChildren(heading,findingTable,observationHeading,observationTable);
    } catch(error) {
      panel.textContent = "Kunne ikke hente scan-detaljer: " + error.message;
    }
  }
  async function loadAuthorizations(domainId) {
    try {
      const rows=await api("/domains/"+domainId+"/authorizations");
      const output=rows.map(a=>{
        const actions=el("div");
        const revoke=el("button","Tilbagekald");revoke.className="danger";
        revoke.disabled=!!a.revoked_at;
        revoke.addEventListener("click",async()=>{try{await api("/authorizations/"+a.authorization_id+"/revoke",{method:"POST"});await loadAuthorizations(domainId);message("Autorisationsgrundlag tilbagekaldt.");}catch(e){message(e.message);}});
        const disable=el("button",a.target_status==="active"?"Deaktivér mål":"Aktivér mål");disable.className="secondary";
        disable.addEventListener("click",async()=>{try{await api("/scan-targets/"+a.scan_target_id,{method:"PATCH",body:JSON.stringify({status:a.target_status==="active"?"disabled":"active"})});await loadAuthorizations(domainId);}catch(e){message(e.message);}});
        actions.append(revoke,disable);
        const now = Date.now();
        const validFrom = new Date(a.valid_from).getTime();
        const validUntil = a.valid_until ? new Date(a.valid_until).getTime() : null;
        let status = "Ukendt status";
        if (a.revoked_at) status = "Tilbagekaldt";
        else if (validFrom > now) status = "Afventer start";
        else if (validUntil !== null && validUntil <= now) status = "Udløbet";
        else if (a.target_status !== "active") status = "Scanmål deaktiveret";
        else if (a.currently_authorized) status = "Aktiv";
        return [
          a.authorization_id, a.basis_type, a.evidence_reference, a.granted_by,
          new Date(a.valid_from).toLocaleString(),
          a.valid_until ? new Date(a.valid_until).toLocaleString() : "Ingen udløbsdato",
          status, actions
        ];
      });
      $("authorizations").replaceChildren(table(["ID","Grundlag","Evidens","Givet af","Gyldig fra","Gyldig til","Status","Handlinger"],output));
    } catch(e){message(e.message);}
  }
  async function pollJob(id) {
    for(let i=0;i<60;i++){
      await new Promise(resolve=>setTimeout(resolve,2000));
      try {
        const job=await api("/scan-jobs/"+id);
        message("Scan-job "+id+": "+job.status+(job.scan_id?" · Scan-ID "+job.scan_id:"")+(job.error?" · "+job.error:""));
        if(["succeeded","failed"].includes(job.status)){scanOffset=0;await refresh();return;}
      } catch(e){message(e.message);return;}
    }
    message("Scan-job "+id+" kører stadig. Opdatér senere for at kontrollere status.");
  }
  $("connect").addEventListener("click", async()=>{
    apiKey=$("key").value.trim();
    try{await refresh();}catch(e){apiKey="";message(e.message);}
  });
  $("refresh").addEventListener("click",refresh);
  $("search-lists").addEventListener("click",refresh);
  $("list-search").addEventListener("keydown",event=>{
    if(event.key==="Enter"){event.preventDefault();refresh();}
  });
  $("scan-prev").addEventListener("click",async()=>{
    scanOffset=Math.max(0,scanOffset-scanPageSize);
    await refresh();
  });
  $("scan-next").addEventListener("click",async()=>{
    scanOffset+=scanPageSize;
    await refresh();
  });
  $("export-csv").addEventListener("click", async () => {
    const button = $("export-csv");
    button.disabled = true;
    try {
      if (!apiKey) throw new Error("Indtast API-nøglen og forbind først.");
      const response = await fetch("/results.csv", {headers: {"X-API-Key": apiKey}});
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || ("HTTP " + response.status));
      }
      const url = URL.createObjectURL(await response.blob());
      const link = el("a");
      link.href = url;
      link.download = "dk-php-scanner-results.csv";
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      message("CSV-eksport hentet.");
    } catch (error) {
      message(error.message);
    } finally {
      button.disabled = false;
    }
  });
  $("prospect-form").addEventListener("submit",async e=>{
    e.preventDefault();
    try{await api("/prospects",{method:"POST",body:JSON.stringify({name:$("prospect-name").value,organization_number:$("prospect-number").value||null,website_url:$("prospect-website").value||null,notes:$("prospect-notes").value})});e.target.reset();await refresh();}
    catch(err){message(err.message);}
  });
  $("domain-form").addEventListener("submit",async e=>{
    e.preventDefault();
    try{const domains=$("domain-import-input").value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);const result=await api("/domains/import",{method:"POST",body:JSON.stringify({domains,source:"operator-ui"})});message("Behandlet: "+result.processed+" · accepteret/eksisterende: "+result.accepted_or_existing+" · afvist: "+result.rejected.length);e.target.reset();await refresh();}
    catch(err){message(err.message);}
  });
  $("associate").addEventListener("click",async()=>{
    try{await api("/prospects/"+Number($("associate-prospect").value)+"/domains",{method:"POST",body:JSON.stringify({domain_id:Number($("associate-domain").value)})});message("Domæne tilknyttet som uverificeret association.");await refresh();}
    catch(e){message(e.message);}
  });
  $("authorization-form").addEventListener("submit",async e=>{
    e.preventDefault();
    try{
      const from=new Date($("auth-from").value);const until=$("auth-until").value?new Date($("auth-until").value):null;
      await api("/domains/"+Number($("auth-domain").value)+"/authorizations",{method:"POST",body:JSON.stringify({
        basis_type:$("auth-type").value,granted_by:$("auth-grantor").value,evidence_reference:$("auth-evidence").value,
        description:$("auth-description").value,valid_from:from.toISOString(),valid_until:until?until.toISOString():null
      })});
      message("Autorisationsgrundlag registreret.");await loadAuthorizations(Number($("auth-domain").value));await refresh();
    }catch(err){message(err.message);}
  });
})();
</script>
</body>
</html>"""
