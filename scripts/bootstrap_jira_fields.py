#!/usr/bin/env python3
"""
Bootstrap de custom fields no Jira Cloud para o issue type "Host Vulnerability".

Cria (de forma idempotente):
  1. cada custom field (se ainda nao existir)
  2. garante que cada field tem um context global (necessario para indexar/pesquisar)
  3. associa cada field a uma screen (default ou as que voce indicar)

Uso:
  export JIRA_BASE_URL="https://SEUSITE.atlassian.net"
  export JIRA_EMAIL="voce@exemplo.com"
  export JIRA_API_TOKEN="seu_token_de_id.atlassian.com"

  # opcional: limitar a quais screens associar (nomes separados por virgula).
  # se nao definir, associa a TODAS as screens (cuidado em prod).
  export JIRA_TARGET_SCREENS="HOSTVULN: Scrum Default Issue Screen"

  python3 jira_bootstrap_fields.py            # cria de verdade
  python3 jira_bootstrap_fields.py --dry-run  # so mostra o que faria

Observacoes:
  - "Searchable=Yes" no Jira Cloud e automatico: todo custom field com context
    fica pesquisavel por JQL. Nao ha flag para setar.
  - "Read-only" nao existe como tipo nativo. "Primary Key" e criado como
    single-line text; o read-only e comportamental (ver nota no final do chat).
  - O Jira NAO impede dois campos com o mesmo nome. Por isso a checagem de
    existencia e feita por nome para evitar duplicatas em re-execucoes.
"""

import argparse
import json
import os
import sys
import time

import requests
from requests.auth import HTTPBasicAuth

# ---------------------------------------------------------------------------
# Tipos de campo do Jira Cloud (type / searcherKey)
# ---------------------------------------------------------------------------
FT = {
    "number": {
        "type": "com.atlassian.jira.plugin.system.customfieldtypes:float",
        "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:exactnumber",
    },
    "text": {  # single line
        "type": "com.atlassian.jira.plugin.system.customfieldtypes:textfield",
        "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:textsearcher",
    },
    "textarea": {  # multi line
        "type": "com.atlassian.jira.plugin.system.customfieldtypes:textarea",
        "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:textsearcher",
    },
    "labels": {
        "type": "com.atlassian.jira.plugin.system.customfieldtypes:labels",
        "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:labelsearcher",
    },
}

# ---------------------------------------------------------------------------
# Definicao dos campos: (Nome, kind, descricao)
# kind in {number, text, textarea, labels}
# Ordem preservada conforme as tabelas enviadas.
# ---------------------------------------------------------------------------
FIELDS = [
    # --- Tabela 1 ---
    ("Host ID",                          "number",   ""),
    ("Asset ID",                         "number",   ""),
    ("IP",                               "text",     ""),
    ("IPV6",                             "text",     ""),
    ("Tracking Method",                  "text",     ""),
    ("OS",                               "text",     ""),
    ("Last Scan Datetime",               "text",     ""),
    ("Last VM Scanned Date",             "text",     ""),
    ("Asset Tag",                        "labels",   ""),
    ("QID",                              "number",   ""),
    ("QDS",                              "number",   "Qualys Detection Score"),
    ("Port",                             "number",   ""),
    ("Severity",                         "number",   ""),
    ("Vuln Type",                        "text",     ""),
    ("Patchable",                        "text",     ""),
    ("PCI Flag",                         "text",     ""),
    ("Vuln Category",                    "text",     ""),
    ("Published Datetime",               "text",     ""),
    ("CVSS Base",                        "number",   ""),
    ("CVSS Temporal",                    "number",   ""),
    ("Detection Status",                 "text",     ""),
    ("CVSS V3 Base",                     "number",   ""),
    ("CVSS V3 Temporal",                 "number",   ""),
    ("Last Service Modification Datetime", "text",   ""),
    ("CVEs",                             "textarea", ""),
    ("Diagnosis",                        "textarea", ""),
    ("Consequence",                      "textarea", ""),
    ("Solution",                         "textarea", ""),
    ("Primary Key",                      "text",     "Read-only: preenchido apenas pelo conector."),
    ("TruRisk Score",                    "number",   ""),
    ("Asset Criticality Score",          "number",   ""),
    # --- Tabela 2 ---
    ("Last VM Scanned Duration",         "number",   "Duracao (em segundos) do scan de vulnerabilidade nao autenticado mais recente no asset."),
    ("Network ID",                       "number",   ""),
    ("DNS",                              "text",     ""),
    ("QG Host ID",                       "text",     "ID do host Qualys atribuido ao asset quando Agentless Tracking e usado ou ha cloud agent instalado."),
    ("Netbios",                          "text",     ""),
    ("Unique Value ID",                  "number",   "ID unico da deteccao da vulnerabilidade. Distingue cada deteccao entre assets, portas, servicos, etc."),
    ("SSL",                              "number",   "1 = vulnerabilidade detectada sobre SSL; 0 = nao detectada sobre SSL."),
    ("Results",                          "textarea", ""),
    ("First Found Datetime",             "text",     ""),
    ("Last Found Datetime",              "text",     ""),
    ("Times Found",                      "number",   ""),
    ("Last Test Datetime",               "text",     ""),
    ("Last Update Datetime",             "text",     ""),
    ("Last Fixed Datetime",              "text",     ""),
    ("Is Ignored",                       "number",   "Booleano. 1 = ignorado, 0 = nao ignorado."),
    ("Is Disabled",                      "number",   "Booleano. 1 = desabilitado, 0 = nao desabilitado."),
    ("Last Processed Datetime",          "text",     ""),
    ("Protocol",                         "text",     ""),
]

# ---------------------------------------------------------------------------
# Cliente HTTP
# ---------------------------------------------------------------------------
class Jira:
    def __init__(self, base, email, token, dry_run=False):
        self.base = base.rstrip("/")
        self.auth = HTTPBasicAuth(email, token)
        self.h = {"Accept": "application/json", "Content-Type": "application/json"}
        self.dry = dry_run

    def _req(self, method, path, **kw):
        url = f"{self.base}{path}"
        for attempt in range(5):
            r = requests.request(method, url, auth=self.auth, headers=self.h, **kw)
            if r.status_code == 429:  # rate limit
                wait = int(r.headers.get("Retry-After", 2 ** attempt))
                print(f"   ...rate limited, aguardando {wait}s")
                time.sleep(wait)
                continue
            return r
        return r

    def get(self, path, **kw):
        return self._req("GET", path, **kw)

    def post(self, path, payload):
        if self.dry:
            print(f"   [dry-run] POST {path} {json.dumps(payload, ensure_ascii=False)[:120]}")
            return None
        return self._req("POST", path, data=json.dumps(payload))

    def put(self, path, payload):
        if self.dry:
            print(f"   [dry-run] PUT {path} {json.dumps(payload, ensure_ascii=False)[:120]}")
            return None
        return self._req("PUT", path, data=json.dumps(payload))


# ---------------------------------------------------------------------------
# Operacoes
# ---------------------------------------------------------------------------
def list_existing_fields(j):
    """Mapa nome -> field dict (apenas custom fields)."""
    r = j.get("/rest/api/3/field")
    r.raise_for_status()
    out = {}
    for f in r.json():
        if f.get("custom"):
            out[f["name"]] = f
    return out


def create_field(j, name, kind, description):
    payload = {
        "name": name,
        "type": FT[kind]["type"],
        "searcherKey": FT[kind]["searcherKey"],
    }
    if description:
        payload["description"] = description
    r = j.post("/rest/api/3/field", payload)
    if r is None:  # dry-run
        return None
    if r.status_code == 201:
        return r.json()
    raise RuntimeError(f"Falha ao criar '{name}': {r.status_code} {r.text}")


def ensure_global_context(j, field_id, field_name):
    """Garante um context global para o campo (necessario p/ pesquisa/uso).
    Campos criados via API ja recebem context default global; esta funcao
    cobre o caso de campos antigos sem context."""
    r = j.get(f"/rest/api/3/field/{field_id}/context")
    if r.status_code != 200:
        return
    if r.json().get("values"):
        return  # ja tem context
    payload = {
        "name": f"{field_name} Global Context",
        "description": "Context global criado pelo bootstrap.",
    }
    j.post(f"/rest/api/3/field/{field_id}/context", payload)


def list_target_screens(j):
    """Retorna lista de screens (id, name) filtrada por JIRA_TARGET_SCREENS se setado."""
    wanted = os.environ.get("JIRA_TARGET_SCREENS", "").strip()
    wanted_set = {w.strip() for w in wanted.split(",") if w.strip()} if wanted else None

    screens, start = [], 0
    while True:
        r = j.get(f"/rest/api/3/screens?startAt={start}&maxResults=100")
        r.raise_for_status()
        data = r.json()
        for s in data.get("values", []):
            if wanted_set is None or s["name"] in wanted_set:
                screens.append((s["id"], s["name"]))
        if data.get("isLast", True):
            break
        start += data.get("maxResults", 100)
    return screens


def get_or_create_default_tab(j, screen_id):
    r = j.get(f"/rest/api/3/screens/{screen_id}/tabs")
    if r.status_code == 200 and r.json():
        return r.json()[0]["id"]
    # cria uma tab se nao houver
    r = j.post(f"/rest/api/3/screens/{screen_id}/tabs", {"name": "Field Tab"})
    return r.json()["id"] if r is not None and r.status_code in (200, 201) else None


def field_in_tab(j, screen_id, tab_id, field_id):
    r = j.get(f"/rest/api/3/screens/{screen_id}/tabs/{tab_id}/fields")
    if r.status_code != 200:
        return False
    return any(f["id"] == field_id for f in r.json())


def add_field_to_screen(j, screen_id, tab_id, field_id):
    if not j.dry and field_in_tab(j, screen_id, tab_id, field_id):
        return "ja-presente"
    r = j.post(f"/rest/api/3/screens/{screen_id}/tabs/{tab_id}/fields", {"fieldId": field_id})
    if r is None:
        return "dry-run"
    if r.status_code in (200, 201):
        return "adicionado"
    # 400 geralmente = ja esta na screen
    return f"skip({r.status_code})"


# ---------------------------------------------------------------------------
# Projeto
# ---------------------------------------------------------------------------
def get_account_id(j):
    r = j.get("/rest/api/3/myself")
    r.raise_for_status()
    return r.json()["accountId"]


def find_project(j, key):
    r = j.get(f"/rest/api/3/project/{key}")
    return r.json() if r.status_code == 200 else None


def create_project(j, key, name, lead_account_id):
    """Cria um projeto COMPANY-MANAGED (classic). E o tipo que funciona com
    custom fields globais + screens via API (team-managed tem campos proprios
    e API limitada, inadequado p/ automacao Jira<->Qualys)."""
    existing = find_project(j, key)
    if existing:
        print(f"   = projeto '{key}' ja existe (id {existing['id']})")
        return existing
    payload = {
        "key": key,
        "name": name,
        "projectTypeKey": "software",
        # template classico => company-managed. Os 'gh-simplified-*' sao team-managed.
        "projectTemplateKey": "com.pyxis.greenhopper.jira:gh-kanban-template",
        "leadAccountId": lead_account_id,
        "assigneeType": "PROJECT_LEAD",
        "description": "Automacao Jira <-> Qualys (host vulnerabilities).",
    }
    r = j.post("/rest/api/3/project", payload)
    if r is None:  # dry-run
        print(f"   + projeto '{key}' [dry-run]")
        return None
    if r.status_code in (200, 201):
        print(f"   + projeto '{key}' criado")
        return find_project(j, key) or r.json()
    raise RuntimeError(f"Falha ao criar projeto '{key}': {r.status_code} {r.text}")


def get_project_screen_ids(j, project_id):
    """Resolve os screen ids realmente usados pelo projeto, via issue type
    screen scheme -> screen schemes -> screens (default/create/edit/view)."""
    screen_ids = set()
    r = j.get(f"/rest/api/3/issuetypescreenscheme/project?projectId={project_id}")
    if r.status_code != 200:
        return screen_ids
    vals = r.json().get("values", [])
    if not vals:
        return screen_ids
    itss_id = vals[0]["issueTypeScreenScheme"]["id"]

    ss_ids, start = set(), 0
    while True:
        r = j.get(f"/rest/api/3/issuetypescreenscheme/mapping"
                  f"?issueTypeScreenSchemeId={itss_id}&startAt={start}&maxResults=100")
        if r.status_code != 200:
            break
        data = r.json()
        for m in data.get("values", []):
            ss_ids.add(m["screenSchemeId"])
        if data.get("isLast", True):
            break
        start += data.get("maxResults", 100)

    for ss_id in ss_ids:
        r = j.get(f"/rest/api/3/screenscheme?id={ss_id}")
        if r.status_code != 200:
            continue
        for ss in r.json().get("values", []):
            for slot in (ss.get("screens") or {}).values():
                if slot:
                    screen_ids.add(slot)
    return screen_ids


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="nao escreve nada, so mostra")
    ap.add_argument("--skip-screens", action="store_true", help="cria fields mas nao associa a screens")
    ap.add_argument("--no-project", action="store_true", help="nao cria/usa projeto (comportamento antigo)")
    ap.add_argument("--project-key", default=os.environ.get("JIRA_PROJECT_KEY", "QVULN"),
                    help="chave do projeto (default: QVULN)")
    ap.add_argument("--project-name", default=os.environ.get("JIRA_PROJECT_NAME", "Qualys Host Vulnerabilities"),
                    help="nome do projeto")
    args = ap.parse_args()

    base = os.environ.get("JIRA_BASE_URL")
    email = os.environ.get("JIRA_EMAIL")
    token = os.environ.get("JIRA_API_TOKEN")
    if not all([base, email, token]):
        sys.exit("Defina JIRA_BASE_URL, JIRA_EMAIL e JIRA_API_TOKEN no ambiente.")

    j = Jira(base, email, token, dry_run=args.dry_run)

    print(f"== Bootstrap em {base} ==")
    print(f"   modo: {'DRY-RUN' if args.dry_run else 'EXECUCAO REAL'}\n")

    # 0) Projeto (company-managed)
    project = None
    if not args.no_project:
        print(f"-> Garantindo projeto '{args.project_key}' ({args.project_name})...")
        lead = get_account_id(j)
        project = create_project(j, args.project_key, args.project_name, lead)
        print()

    # 1) Campos
    print("-> Lendo campos existentes...")
    existing = list_existing_fields(j)
    print(f"   {len(existing)} custom fields ja existem na instancia.\n")

    created, reused = [], []
    name_to_id = {}

    print("-> Criando campos...")
    for name, kind, desc in FIELDS:
        if name in existing:
            fid = existing[name]["id"]
            name_to_id[name] = fid
            reused.append(name)
            continue
        res = create_field(j, name, kind, desc)
        if res is None:  # dry-run
            name_to_id[name] = None
            continue
        fid = res["id"]
        name_to_id[name] = fid
        created.append(name)
        ensure_global_context(j, fid, name)
        time.sleep(0.15)  # gentil com rate limit
    print(f"   criados: {len(created)} | reaproveitados: {len(reused)}\n")

    # 2) Screens do projeto
    if args.skip_screens:
        print("-> --skip-screens: pulando associacao a screens.")
    else:
        print("-> Associando campos as screens...")
        if project and project.get("id"):
            screens = [(sid, f"screen {sid}") for sid in sorted(get_project_screen_ids(j, project["id"]))]
            print(f"   ({len(screens)} screens do projeto '{project.get('key')}')")
        else:
            screens = list_target_screens(j)
        if not screens:
            print("   (nenhuma screen alvo encontrada)")
        for sid, sname in screens:
            tab_id = get_or_create_default_tab(j, sid)
            if tab_id is None:
                print(f"   ! {sname} sem tab acessivel, pulando")
                continue
            ok = 0
            for name, fid in name_to_id.items():
                if not fid:
                    continue
                status = add_field_to_screen(j, sid, tab_id, fid)
                if status in ("adicionado", "ja-presente", "dry-run"):
                    ok += 1
                time.sleep(0.05)
            print(f"   {sname}: {ok} campos garantidos")

    # 3) Validacao automatica
    print("\n== Resumo ==")
    print(f"   projeto: {project.get('key') if project else '(nenhum)'}")
    print(f"   campos criados: {len(created)} | reaproveitados: {len(reused)}")
    if project and project.get("id") and not args.skip_screens and not args.dry_run:
        our_ids = {fid for fid in name_to_id.values() if fid}
        on_screen = set()
        for sid in get_project_screen_ids(j, project["id"]):
            r = j.get(f"/rest/api/3/screens/{sid}/tabs")
            if r.status_code != 200 or not r.json():
                continue
            tab_id = r.json()[0]["id"]
            fr = j.get(f"/rest/api/3/screens/{sid}/tabs/{tab_id}/fields")
            if fr.status_code == 200:
                on_screen |= {f["id"] for f in fr.json() if f["id"] in our_ids}
        print(f"   VALIDACAO: {len(on_screen)}/{len(our_ids)} campos presentes nas screens do projeto")


if __name__ == "__main__":
    main()
