#!/usr/bin/env python3
"""Standalone probe: confirm the *exact* Internet-facing tag string in Qualys.

This is deliberately independent of the qjsync package (like
``bootstrap_jira_fields.py``) so you can confirm the exposure tag BEFORE the full
connector is built. It hits Host List Detection with ``show_tags=1`` and prints
the asset tags that are actually APPLIED to real hosts — a tag that exists in the
console but isn't applied to anything is useless to the exposure rules.

Why this matters: the prioritisation Layer 1 keys off
``asset_tags contains "<exposure tag>"``. If that string doesn't match the real
tag, the whole exposure layer silently never fires (None-safe contains -> False)
and you'd never see an error — just wrong priorities.

Usage:
  export QUALYS_API_URL="https://qualysapi.qg2.apps.qualys.com"   # your POD, no /api
  export QUALYS_USERNAME="..."
  export QUALYS_PASSWORD="..."

  # A) Discover: sample hosts and list the DISTINCT applied tag names (+counts).
  python3 scripts/probe_qualys_tags.py --sample 100

  # B) Confirm: for a host you KNOW is internet-facing, print its tags.
  python3 scripts/probe_qualys_tags.py --ip 203.0.113.10
  python3 scripts/probe_qualys_tags.py --ids 123456

Then set the confirmed string as the `value:` in the exposure rules of rules.yml.
"""

from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter

import requests
from requests.auth import HTTPBasicAuth

HLD_ENDPOINT = "/api/2.0/fo/asset/host/vm/detection/"


def _env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        sys.exit(f"Defina {name} no ambiente (veja o cabecalho do script).")
    return val


def fetch(api_url: str, auth: HTTPBasicAuth, params: dict[str, str]) -> bytes:
    url = f"{api_url.rstrip('/')}{HLD_ENDPOINT}"
    # X-Requested-With is mandatory for the Qualys API.
    headers = {"X-Requested-With": "qjsync-probe"}
    r = requests.post(url, auth=auth, headers=headers, data=params, timeout=120)
    if r.status_code != 200:
        sys.exit(f"Qualys HTTP {r.status_code}: {r.text[:500]}")
    return r.content


def iter_hosts(xml: bytes):
    root = ET.fromstring(xml)
    for host in root.iter("HOST"):
        hid = host.findtext("ID")
        ip = host.findtext("IP")
        tracking = host.findtext("TRACKING_METHOD")
        dns = host.findtext("DNS")
        tags = [t.text for t in host.findall("./TAGS/TAG/NAME") if t.text]
        yield {"id": hid, "ip": ip, "dns": dns, "tracking": tracking, "tags": tags}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ip", help="confirmar tags de um host exposto especifico (por IP)")
    ap.add_argument("--ids", help="idem por Host ID")
    ap.add_argument("--sample", type=int, default=0,
                    help="descobrir: amostra N hosts e lista nomes de tag distintos")
    args = ap.parse_args()

    api_url = _env("QUALYS_API_URL")
    auth = HTTPBasicAuth(_env("QUALYS_USERNAME"), _env("QUALYS_PASSWORD"))

    params: dict[str, str] = {"action": "list", "show_tags": "1"}
    if args.ip:
        params["ips"] = args.ip
    elif args.ids:
        params["ids"] = args.ids
    else:
        params["truncation_limit"] = str(args.sample or 100)

    print(f"-> POST {api_url}{HLD_ENDPOINT}  params={ {k: v for k, v in params.items()} }")
    hosts = list(iter_hosts(fetch(api_url, auth, params)))
    if not hosts:
        print("Nenhum host retornado. Confira o filtro/credenciais.")
        return

    if args.ip or args.ids:
        for h in hosts:
            print(f"\nHost {h['id']}  IP={h['ip']}  DNS={h['dns']}  TRACKING={h['tracking']}")
            if h["tags"]:
                print("  TAGS aplicadas:")
                for t in h["tags"]:
                    print(f"    - {t!r}")
            else:
                print("  (NENHUMA tag aplicada — show_tags ligado, host sem tags)")
    else:
        counter: Counter[str] = Counter()
        tracking: Counter[str] = Counter()
        for h in hosts:
            counter.update(h["tags"])
            if h["tracking"]:
                tracking[h["tracking"]] += 1
        print(f"\n{len(hosts)} hosts amostrados.")
        print("\nTAGS distintas aplicadas (nome -> nº de hosts):")
        for name, n in counter.most_common():
            print(f"  {n:>4}  {name!r}")
        print("\nTRACKING_METHOD distintos (p/ confirmar agente vs scan de rede):")
        for name, n in tracking.most_common():
            print(f"  {n:>4}  {name!r}")
        print("\nProcure o nome exato da tag de exposicao (ex. 'Internet Facing', "
              "'External', 'Internet-Exposed') e use-o como `value:` nas regras Layer 1.")


if __name__ == "__main__":
    main()
