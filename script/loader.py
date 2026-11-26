import csv
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx


# ==============================================================================
# 1. EXCEPTIONS PERSONNALISÉES POUR LA VALIDATION
# ==============================================================================

class NetworkValidationError(Exception):
    """Exception levée lorsqu'une erreur structurelle ou logique est détectée dans network.json."""


# ==============================================================================
# 2. STRUCTURES DE DONNÉES DU MODÈLE SYSTÈME
# ==============================================================================

@dataclass
class Zone:
    id: str
    trusted: bool


@dataclass
class Service:
    name: str
    product: str
    version: str
    port: int


@dataclass
class Vulnerability:
    cve: str
    service: str


@dataclass
class Misconfiguration:
    id: str
    description: str
    service: str
    grants: str


@dataclass
class Account:
    user: str
    privilege: str


@dataclass
class Host:
    id: str
    name: str
    zone: str
    os: str
    role: str
    criticality: int
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    misconfigurations: List[Misconfiguration] = field(default_factory=list)
    accounts: List[Account] = field(default_factory=list)
    data_assets: List[str] = field(default_factory=list)


@dataclass
class FirewallRule:
    src_zone: str
    src_host: str
    dst_zone: str
    dst_host: str
    ports: List[int]
    action: str


@dataclass
class TrustRelation:
    id: str
    from_host: str
    to_host: str
    type: str
    grants: str
    requires: Optional[str] = None


@dataclass
class DataFlow:
    id: str
    src: str
    dst: str
    protocol: str
    data: str


@dataclass
class SystemModel:
    metadata: Dict[str, Any]
    zones: Dict[str, Zone]
    hosts: Dict[str, Host]
    firewall_rules: List[FirewallRule]
    trust_relations: List[TrustRelation]
    data_flows: List[DataFlow]
    attacker_scenarios: List[Dict[str, Any]]
    goals: List[Dict[str, Any]]
    mitigations: List[Dict[str, Any]]
    total_mitigation_cost: int
    external_entities: Set[str] = field(default_factory=set)
    dfd_graph: Optional[nx.MultiDiGraph] = None
    reachability_matrix: Dict[str, Dict[str, List[Dict[str, Any]]]] = field(default_factory=dict)


# ==============================================================================
# 3. VALIDATEUR ET PARSER (LOADER)
# ==============================================================================

class NetworkLoader:
    """Classe responsable du chargement, de la validation et de la modélisation du réseau."""

    VALID_PRIVILEGES = {"none", "user", "root"}
    VALID_FIREWALL_ACTIONS = {"allow", "deny"}

    def __init__(self, json_path: str):
        self.json_path = Path(json_path)

    def load_and_validate(self) -> SystemModel:
        """Charge le fichier JSON, valide toutes les contraintes et construit le SystemModel."""
        if not self.json_path.exists():
            raise FileNotFoundError(f"Fichier introuvable : {self.json_path}")

        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as exc:
            raise NetworkValidationError(
                f"JSON malformé à la ligne {exc.lineno}, colonne {exc.colno} : {exc.msg}"
            ) from exc

        if not isinstance(raw_data, dict):
            raise NetworkValidationError("La racine du document JSON doit être un objet (dict).")

        self._validate_top_level_keys(raw_data)
        metadata = self._validate_metadata(raw_data["metadata"])
        net_data = raw_data["network"]
        if not isinstance(net_data, dict):
            raise NetworkValidationError("La clé 'network' doit être un objet JSON.")

        zones = self._validate_zones(net_data.get("zones"))
        hosts = self._validate_hosts(net_data.get("hosts"), zones, metadata["hosts"])
        firewall_rules = self._validate_firewall_rules(
            net_data.get("firewall_rules"), zones, hosts
        )
        trust_relations = self._validate_trust_relations(
            net_data.get("trust_relations"), hosts
        )
        data_flows, external_entities = self._validate_data_flows(
            net_data.get("data_flows"), hosts
        )
        attacker_scenarios = self._validate_attacker_scenarios(
            raw_data["attacker_scenarios"], zones, hosts
        )
        goals = self._validate_goals(raw_data["goals"], hosts)
        mitigations, total_cost = self._validate_mitigations(
            raw_data["mitigations"],
            raw_data.get("total_mitigation_cost"),
            zones,
            hosts,
            trust_relations,
        )

        model = SystemModel(
            metadata=metadata,
            zones=zones,
            hosts=hosts,
            firewall_rules=firewall_rules,
            trust_relations=trust_relations,
            data_flows=data_flows,
            attacker_scenarios=attacker_scenarios,
            goals=goals,
            mitigations=mitigations,
            total_mitigation_cost=total_cost,
            external_entities=external_entities,
        )

        model.reachability_matrix = self._build_reachability_matrix(model)
        model.dfd_graph = self._build_dfd_graph(model)
        return model

    def _validate_top_level_keys(self, data: Dict[str, Any]) -> None:
        required_keys = {
            "metadata",
            "network",
            "attacker_scenarios",
            "goals",
            "mitigations",
            "total_mitigation_cost",
        }
        missing = required_keys - set(data.keys())
        if missing:
            raise NetworkValidationError(
                f"Clés obligatoires manquantes à la racine : {sorted(missing)}"
            )

    def _validate_metadata(self, meta: Any) -> Dict[str, Any]:
        if not isinstance(meta, dict):
            raise NetworkValidationError("'metadata' doit être un objet.")
        for req in ("name", "version", "hosts", "cvss_version"):
            if req not in meta:
                raise NetworkValidationError(f"Champ obligatoire manquant dans metadata : '{req}'")
        if not isinstance(meta["hosts"], int) or meta["hosts"] <= 0:
            raise NetworkValidationError("'metadata.hosts' doit être un entier strictement positif.")
        return meta

    def _validate_zones(self, raw_zones: Any) -> Dict[str, Zone]:
        if not isinstance(raw_zones, list) or not raw_zones:
            raise NetworkValidationError("'network.zones' doit être une liste non vide.")
        zones: Dict[str, Zone] = {}
        for idx, z in enumerate(raw_zones):
            if not isinstance(z, dict) or "id" not in z or "trusted" not in z:
                raise NetworkValidationError(
                    f"Zone invalide à l'index {idx} : 'id' et 'trusted' sont requis."
                )
            if not isinstance(z["id"], str) or not z["id"].strip():
                raise NetworkValidationError(f"Identifiant de zone invalide à l'index {idx}.")
            if not isinstance(z["trusted"], bool):
                raise NetworkValidationError(
                    f"La propriété 'trusted' de la zone '{z['id']}' doit être un booléen."
                )
            if z["id"] in zones:
                raise NetworkValidationError(f"Identifiant de zone dupliqué : '{z['id']}'")
            zones[z["id"]] = Zone(id=z["id"], trusted=z["trusted"])
        return zones

    def _validate_hosts(
        self, raw_hosts: Any, zones: Dict[str, Zone], expected_count: int
    ) -> Dict[str, Host]:
        if not isinstance(raw_hosts, list) or not raw_hosts:
            raise NetworkValidationError("'network.hosts' doit être une liste non vide.")
        if len(raw_hosts) != expected_count:
            raise NetworkValidationError(
                f"Incohérence du nombre d'hôtes : metadata.hosts={expected_count}, "
                f"mais {len(raw_hosts)} hôtes définis."
            )

        hosts: Dict[str, Host] = {}
        for idx, h in enumerate(raw_hosts):
            if not isinstance(h, dict):
                raise NetworkValidationError(f"L'hôte à l'index {idx} doit être un objet.")
            required = {"id", "name", "zone", "os", "role", "criticality", "services", "accounts"}
            missing = required - set(h.keys())
            if missing:
                raise NetworkValidationError(
                    f"Hôte à l'index {idx} ({h.get('id', '?')}) : clés manquantes {sorted(missing)}"
                )

            hid = h["id"]
            if hid in hosts:
                raise NetworkValidationError(f"Identifiant d'hôte dupliqué : '{hid}'")
            if h["zone"] not in zones:
                raise NetworkValidationError(
                    f"Hôte '{hid}' référence une zone inexistante : '{h['zone']}'"
                )
            if not isinstance(h["criticality"], int) or not (1 <= h["criticality"] <= 5):
                raise NetworkValidationError(
                    f"Hôte '{hid}' : 'criticality' doit être un entier entre 1 et 5."
                )

            services: List[Service] = []
            service_names: Set[str] = set()
            if not isinstance(h["services"], list):
                raise NetworkValidationError(f"Hôte '{hid}' : 'services' doit être une liste.")
            for s in h["services"]:
                if not isinstance(s, dict) or not {"name", "product", "version", "port"} <= set(s.keys()):
                    raise NetworkValidationError(f"Service malformé sur l'hôte '{hid}'.")
                if not isinstance(s["port"], int) or not (0 <= s["port"] <= 65535):
                    raise NetworkValidationError(
                        f"Port invalide ({s['port']}) pour le service '{s['name']}' sur '{hid}'."
                    )
                services.append(
                    Service(
                        name=s["name"],
                        product=s["product"],
                        version=s["version"],
                        port=s["port"],
                    )
                )
                service_names.add(s["name"])

            vulns: List[Vulnerability] = []
            for v in h.get("vulnerabilities", []):
                if not isinstance(v, dict) or "cve" not in v or "service" not in v:
                    raise NetworkValidationError(f"Vulnérabilité malformée sur l'hôte '{hid}'.")
                if not v["cve"].startswith("CVE-"):
                    raise NetworkValidationError(
                        f"Format CVE invalide '{v['cve']}' sur l'hôte '{hid}'."
                    )
                if v["service"] not in service_names:
                    raise NetworkValidationError(
                        f"Hôte '{hid}' : la vulnérabilité '{v['cve']}' référence un service "
                        f"inexistant '{v['service']}'."
                    )
                vulns.append(Vulnerability(cve=v["cve"], service=v["service"]))

            misconfigs: List[Misconfiguration] = []
            for mc in h.get("misconfigurations", []):
                if not isinstance(mc, dict) or not {"id", "description", "service", "grants"} <= set(mc.keys()):
                    raise NetworkValidationError(f"Mauvaise configuration malformée sur '{hid}'.")
                if mc["service"] not in service_names:
                    raise NetworkValidationError(
                        f"Hôte '{hid}' : misconfiguration '{mc['id']}' référence un service "
                        f"inexistant '{mc['service']}'."
                    )
                if mc["grants"] not in self.VALID_PRIVILEGES:
                    raise NetworkValidationError(
                        f"Hôte '{hid}' : privilège 'grants' invalide '{mc['grants']}' sur '{mc['id']}'."
                    )
                misconfigs.append(
                    Misconfiguration(
                        id=mc["id"],
                        description=mc["description"],
                        service=mc["service"],
                        grants=mc["grants"],
                    )
                )

            accounts: List[Account] = []
            if not isinstance(h["accounts"], list) or not h["accounts"]:
                raise NetworkValidationError(f"Hôte '{hid}' : au moins un compte est requis.")
            for acc in h["accounts"]:
                if not isinstance(acc, dict) or "user" not in acc or "privilege" not in acc:
                    raise NetworkValidationError(f"Compte malformé sur l'hôte '{hid}'.")
                if acc["privilege"] not in self.VALID_PRIVILEGES:
                    raise NetworkValidationError(
                        f"Hôte '{hid}' : privilège de compte invalide '{acc['privilege']}'."
                    )
                accounts.append(Account(user=acc["user"], privilege=acc["privilege"]))

            data_assets = h.get("data_assets", [])
            if not isinstance(data_assets, list) or not all(isinstance(d, str) for d in data_assets):
                raise NetworkValidationError(f"Hôte '{hid}' : 'data_assets' doit être une liste de chaînes.")

            hosts[hid] = Host(
                id=hid,
                name=h["name"],
                zone=h["zone"],
                os=h["os"],
                role=h["role"],
                criticality=h["criticality"],
                services=services,
                vulnerabilities=vulns,
                misconfigurations=misconfigs,
                accounts=accounts,
                data_assets=data_assets,
            )

        return hosts

    def _validate_firewall_rules(
        self, raw_rules: Any, zones: Dict[str, Zone], hosts: Dict[str, Host]
    ) -> List[FirewallRule]:
        if not isinstance(raw_rules, list):
            raise NetworkValidationError("'network.firewall_rules' doit être une liste.")
        rules: List[FirewallRule] = []
        for idx, r in enumerate(raw_rules):
            req = {"src_zone", "src_host", "dst_zone", "dst_host", "ports", "action"}
            if not isinstance(r, dict) or not req <= set(r.keys()):
                raise NetworkValidationError(f"Règle pare-feu malformée à l'index {idx}.")
            if r["src_zone"] not in zones:
                raise NetworkValidationError(
                    f"Règle pare-feu #{idx} : src_zone inconnue '{r['src_zone']}'."
                )
            if r["dst_zone"] not in zones:
                raise NetworkValidationError(
                    f"Règle pare-feu #{idx} : dst_zone inconnue '{r['dst_zone']}'."
                )
            if r["src_host"] != "*" and r["src_host"] not in hosts:
                raise NetworkValidationError(
                    f"Règle pare-feu #{idx} : src_host inconnu '{r['src_host']}'."
                )
            if r["dst_host"] != "*" and r["dst_host"] not in hosts:
                raise NetworkValidationError(
                    f"Règle pare-feu #{idx} : dst_host inconnu '{r['dst_host']}'."
                )
            if r["src_host"] != "*" and hosts[r["src_host"]].zone != r["src_zone"]:
                raise NetworkValidationError(
                    f"Règle pare-feu #{idx} : src_host '{r['src_host']}' n'appartient pas à '{r['src_zone']}'."
                )
            if r["dst_host"] != "*" and hosts[r["dst_host"]].zone != r["dst_zone"]:
                raise NetworkValidationError(
                    f"Règle pare-feu #{idx} : dst_host '{r['dst_host']}' n'appartient pas à '{r['dst_zone']}'."
                )
            if r["action"] not in self.VALID_FIREWALL_ACTIONS:
                raise NetworkValidationError(
                    f"Règle pare-feu #{idx} : action invalide '{r['action']}'."
                )
            if not isinstance(r["ports"], list) or not all(
                isinstance(p, int) and 1 <= p <= 65535 for p in r["ports"]
            ):
                raise NetworkValidationError(f"Règle pare-feu #{idx} : liste de ports invalide.")

            rules.append(
                FirewallRule(
                    src_zone=r["src_zone"],
                    src_host=r["src_host"],
                    dst_zone=r["dst_zone"],
                    dst_host=r["dst_host"],
                    ports=r["ports"],
                    action=r["action"],
                )
            )
        return rules

    def _validate_trust_relations(
        self, raw_trusts: Any, hosts: Dict[str, Host]
    ) -> List[TrustRelation]:
        if not isinstance(raw_trusts, list):
            raise NetworkValidationError("'network.trust_relations' doit être une liste.")
        trusts: List[TrustRelation] = []
        seen_ids: Set[str] = set()
        for idx, t in enumerate(raw_trusts):
            req = {"id", "from_host", "to_host", "type", "grants"}
            if not isinstance(t, dict) or not req <= set(t.keys()):
                raise NetworkValidationError(f"Relation de confiance malformée à l'index {idx}.")
            if t["id"] in seen_ids:
                raise NetworkValidationError(f"ID de relation de confiance dupliqué : '{t['id']}'.")
            seen_ids.add(t["id"])
            if t["from_host"] not in hosts:
                raise NetworkValidationError(
                    f"Trust '{t['id']}' : from_host inconnu '{t['from_host']}'."
                )
            if t["to_host"] not in hosts:
                raise NetworkValidationError(
                    f"Trust '{t['id']}' : to_host inconnu '{t['to_host']}'."
                )
            if t["grants"] not in self.VALID_PRIVILEGES:
                raise NetworkValidationError(
                    f"Trust '{t['id']}' : privilège 'grants' invalide '{t['grants']}'."
                )
            trusts.append(
                TrustRelation(
                    id=t["id"],
                    from_host=t["from_host"],
                    to_host=t["to_host"],
                    type=t["type"],
                    grants=t["grants"],
                    requires=t.get("requires"),
                )
            )
        return trusts

    def _validate_data_flows(
        self, raw_flows: Any, hosts: Dict[str, Host]
    ) -> Tuple[List[DataFlow], Set[str]]:
        if not isinstance(raw_flows, list):
            raise NetworkValidationError("'network.data_flows' doit être une liste.")
        flows: List[DataFlow] = []
        external_entities: Set[str] = set()
        seen_ids: Set[str] = set()

        for idx, f in enumerate(raw_flows):
            req = {"id", "src", "dst", "protocol", "data"}
            if not isinstance(f, dict) or not req <= set(f.keys()):
                raise NetworkValidationError(f"Flux de données malformé à l'index {idx}.")
            if f["id"] in seen_ids:
                raise NetworkValidationError(f"ID de flux dupliqué : '{f['id']}'.")
            seen_ids.add(f["id"])

            for endpoint_key in ("src", "dst"):
                endpoint = f[endpoint_key]
                if endpoint.startswith("ext-"):
                    external_entities.add(endpoint)
                elif endpoint not in hosts:
                    raise NetworkValidationError(
                        f"Flux '{f['id']}' : extrémité '{endpoint_key}' inconnue '{endpoint}'."
                    )

            flows.append(
                DataFlow(
                    id=f["id"],
                    src=f["src"],
                    dst=f["dst"],
                    protocol=f["protocol"],
                    data=f["data"],
                )
            )
        return flows, external_entities

    def _validate_attacker_scenarios(
        self, raw_scenarios: Any, zones: Dict[str, Zone], hosts: Dict[str, Host]
    ) -> List[Dict[str, Any]]:
        if not isinstance(raw_scenarios, list) or not raw_scenarios:
            raise NetworkValidationError("'attacker_scenarios' doit être une liste non vide.")
        for idx, sc in enumerate(raw_scenarios):
            if not isinstance(sc, dict) or "id" not in sc or "name" not in sc:
                raise NetworkValidationError(f"Scénario attaquant malformé à l'index {idx}.")
            if "entry_zone" not in sc and "entry_host" not in sc:
                raise NetworkValidationError(
                    f"Scénario '{sc['id']}' : 'entry_zone' ou 'entry_host' est requis."
                )
            if "entry_zone" in sc and sc["entry_zone"] not in zones:
                raise NetworkValidationError(
                    f"Scénario '{sc['id']}' : entry_zone inconnue '{sc['entry_zone']}'."
                )
            if "entry_host" in sc and sc["entry_host"] not in hosts:
                raise NetworkValidationError(
                    f"Scénario '{sc['id']}' : entry_host inconnu '{sc['entry_host']}'."
                )
            if sc.get("initial_privilege") not in self.VALID_PRIVILEGES:
                raise NetworkValidationError(
                    f"Scénario '{sc['id']}' : initial_privilege invalide '{sc.get('initial_privilege')}'."
                )
        return raw_scenarios

    def _validate_goals(
        self, raw_goals: Any, hosts: Dict[str, Host]
    ) -> List[Dict[str, Any]]:
        if not isinstance(raw_goals, list) or not raw_goals:
            raise NetworkValidationError("'goals' doit être une liste non vide.")
        for idx, g in enumerate(raw_goals):
            req = {"id", "host", "privilege", "property", "description"}
            if not isinstance(g, dict) or not req <= set(g.keys()):
                raise NetworkValidationError(f"Objectif malformé à l'index {idx}.")
            if g["host"] not in hosts:
                raise NetworkValidationError(f"Objectif '{g['id']}' : hôte inconnu '{g['host']}'.")
            if g["privilege"] not in self.VALID_PRIVILEGES:
                raise NetworkValidationError(
                    f"Objectif '{g['id']}' : privilège invalide '{g['privilege']}'."
                )
        return raw_goals

    def _validate_mitigations(
        self,
        raw_mitigations: Any,
        declared_total: Any,
        zones: Dict[str, Zone],
        hosts: Dict[str, Host],
        trusts: List[TrustRelation],
    ) -> Tuple[List[Dict[str, Any]], int]:
        if not isinstance(raw_mitigations, list) or not raw_mitigations:
            raise NetworkValidationError("'mitigations' doit être une liste non vide.")

        valid_trust_ids = {t.id for t in trusts}
        valid_mc_ids = {mc.id for h in hosts.values() for mc in h.misconfigurations}
        computed_total = 0

        for idx, m in enumerate(raw_mitigations):
            req = {"id", "name", "cost", "type"}
            if not isinstance(m, dict) or not req <= set(m.keys()):
                raise NetworkValidationError(f"Mitigation malformée à l'index {idx}.")
            if not isinstance(m["cost"], (int, float)) or m["cost"] < 0:
                raise NetworkValidationError(f"Mitigation '{m['id']}' : coût invalide.")
            computed_total += m["cost"]

            mtype = m["type"]
            if mtype == "patch":
                for target in m.get("targets", []):
                    if not isinstance(target, list) or len(target) != 2:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : cible patch malformée {target}."
                        )
                    hid, cve = target
                    if hid not in hosts:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : hôte inconnu '{hid}'."
                        )
                    host_cves = {v.cve for v in hosts[hid].vulnerabilities}
                    if cve not in host_cves:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : CVE '{cve}' absente de l'hôte '{hid}'."
                        )
            elif mtype == "fix_misconfig":
                for mc_id in m.get("targets", []):
                    if mc_id not in valid_mc_ids:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : misconfiguration inconnue '{mc_id}'."
                        )
            elif mtype == "remove_trust":
                for tid in m.get("trusts", []):
                    if tid not in valid_trust_ids:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : trust relation inconnue '{tid}'."
                        )
            elif mtype == "block_flow":
                for fl in m.get("flows", []):
                    if not isinstance(fl, list) or len(fl) != 3:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : flux bloqué malformé {fl}."
                        )
                    src, dst, _port = fl
                    if src not in hosts and src not in zones:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : source inconnue '{src}'."
                        )
                    if dst not in hosts and dst not in zones:
                        raise NetworkValidationError(
                            f"Mitigation '{m['id']}' : destination inconnue '{dst}'."
                        )
            elif mtype in {"scale_time", "detect_only"}:
                pass
            else:
                raise NetworkValidationError(
                    f"Mitigation '{m['id']}' : type inconnu '{mtype}'."
                )

        if declared_total is not None and computed_total != declared_total:
            raise NetworkValidationError(
                f"Coût total incohérent : déclaré={declared_total}, calculé={computed_total}"
            )

        return raw_mitigations, int(computed_total)

    # ==========================================================================
    # 4. MATRICE D'ATTEIGNABILITÉ
    # ==========================================================================

    def _build_reachability_matrix(
        self, model: SystemModel
    ) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """
        Construit la matrice d'atteignabilité entre toutes les sources possibles
        (zone 'internet' + hôtes H01..H27) et tous les hôtes cibles (H01..H27).
        """
        sources = ["internet"] + list(model.hosts.keys())
        targets = list(model.hosts.keys())
        matrix: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
            s: {t: [] for t in targets} for s in sources
        }

        for src in sources:
            src_zone = "internet" if src == "internet" else model.hosts[src].zone
            for dst in targets:
                if src == dst:
                    continue
                dst_host = model.hosts[dst]
                dst_zone = dst_host.zone
                listening_ports = {s.port: s.name for s in dst_host.services if s.port > 0}

                allowed_ports: Set[int] = set()
                rule_sources: Dict[int, str] = {}

                for rule in model.firewall_rules:
                    if rule.action != "allow":
                        continue
                    if rule.src_zone != src_zone or rule.dst_zone != dst_zone:
                        continue
                    if rule.src_host != "*" and rule.src_host != src:
                        continue
                    if rule.dst_host != "*" and rule.dst_host != dst:
                        continue
                    for p in rule.ports:
                        if p in listening_ports:
                            allowed_ports.add(p)
                            rule_sources[p] = "firewall_rule"

                if src != "internet" and src_zone == dst_zone and model.zones[src_zone].trusted:
                    for p in listening_ports:
                        if p not in allowed_ports:
                            allowed_ports.add(p)
                            rule_sources[p] = "intra_zone_lan"

                for p in sorted(allowed_ports):
                    matrix[src][dst].append(
                        {
                            "port": p,
                            "service": listening_ports[p],
                            "via": rule_sources[p],
                        }
                    )

        return matrix

    # ==========================================================================
    # 5. CONSTRUCTION DU GRAPHE DFD (NIVEAU 1)
    # ==========================================================================

    def _build_dfd_graph(self, model: SystemModel) -> nx.MultiDiGraph:
        """Construit un graphe orienté représentant le DFD Niveau 1."""
        g = nx.MultiDiGraph(name="ACME_Retail_DFD_Level1")

        for ext in sorted(model.external_entities):
            g.add_node(
                ext,
                dfd_type="external_entity",
                zone="internet",
                trusted=False,
                label=ext,
            )

        for hid, host in model.hosts.items():
            zone_trusted = model.zones[host.zone].trusted
            g.add_node(
                hid,
                dfd_type="process",
                zone=host.zone,
                trusted=zone_trusted,
                name=host.name,
                role=host.role,
                criticality=host.criticality,
                label=f"{hid}: {host.name}\n({host.role})",
            )

            for asset in host.data_assets:
                ds_id = f"DS_{hid}_{asset}"
                g.add_node(
                    ds_id,
                    dfd_type="data_store",
                    zone=host.zone,
                    trusted=zone_trusted,
                    host=hid,
                    label=asset,
                )
                g.add_edge(
                    hid,
                    ds_id,
                    edge_type="store_access",
                    protocol="local-io",
                    data=asset,
                    crosses_trust_boundary=False,
                )

        for flow in model.data_flows:
            src_zone = "internet" if flow.src.startswith("ext-") else model.hosts[flow.src].zone
            dst_zone = "internet" if flow.dst.startswith("ext-") else model.hosts[flow.dst].zone
            src_trusted = model.zones[src_zone].trusted
            dst_trusted = model.zones[dst_zone].trusted
            crosses_tb = (src_trusted != dst_trusted) or (src_zone != dst_zone)

            g.add_edge(
                flow.src,
                flow.dst,
                id=flow.id,
                edge_type="data_flow",
                protocol=flow.protocol,
                data=flow.data,
                src_zone=src_zone,
                dst_zone=dst_zone,
                crosses_trust_boundary=crosses_tb,
            )

        return g


# ==============================================================================
# 6. EXPORT DES ARTEFACTS (MATRICE & DFD NIVEAU 1 PNG)
# ==============================================================================

def export_dfd_level1_png(model: SystemModel, output_png: Path) -> None:
    """Génère une visualisation du DFD Niveau 1 en PNG avec zones et frontière de confiance."""
    import matplotlib.patches as mpatches
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(22, 14), dpi=180)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    zone_boxes = {
        "internet": (2, 74, 20, 21, "#fdecea", "#c62828", "ZONE: INTERNET (Untrusted)"),
        "dmz": (2, 38, 20, 32, "#fff3e0", "#ef6c00", "ZONE: DMZ (Untrusted)"),
        "corp-lan": (28, 68, 32, 27, "#e8f5e9", "#2e7d32", "ZONE: CORP-LAN (Trusted)"),
        "dev-lan": (28, 38, 32, 26, "#e3f2fd", "#1565c0", "ZONE: DEV-LAN (Trusted)"),
        "mgmt": (28, 6, 32, 28, "#f3e5f5", "#6a1b9a", "ZONE: MGMT (Trusted)"),
        "server-lan": (65, 44, 33, 51, "#e0f2f1", "#00695c", "ZONE: SERVER-LAN (Trusted)"),
        "db-zone": (65, 6, 33, 34, "#ede7f6", "#4527a0", "ZONE: DB-ZONE (Trusted)"),
    }

    for z_id, (x, y, w, h, fc, ec, title) in zone_boxes.items():
        rect = mpatches.FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.6,rounding_size=1.2",
            facecolor=fc,
            edgecolor=ec,
            linewidth=2.0,
            linestyle="--" if not model.zones[z_id].trusted else "-",
            zorder=1,
        )
        ax.add_patch(rect)
        ax.text(
            x + 1.0,
            y + h - 1.8,
            title,
            fontsize=9.5,
            fontweight="bold",
            color=ec,
            zorder=2,
        )

    ax.plot([25, 25], [3, 97], color="#d32f2f", linestyle="-.", linewidth=2.5, zorder=3)
    ax.text(
        25,
        98,
        "TRUST BOUNDARY (Untrusted <-> Trusted)",
        color="#d32f2f",
        fontsize=10,
        fontweight="bold",
        ha="center",
    )

    node_coords: Dict[str, Tuple[float, float]] = {}

    ext_list = sorted(model.external_entities)
    for idx, ext in enumerate(ext_list):
        nx_pos = 12
        ny_pos = 89 - idx * 6.0
        node_coords[ext] = (nx_pos, ny_pos)
        box = mpatches.FancyBboxPatch(
            (nx_pos - 7.5, ny_pos - 1.8),
            15,
            3.6,
            boxstyle="square,pad=0.2",
            facecolor="#ffffff",
            edgecolor="#b71c1c",
            linewidth=1.5,
            zorder=4,
        )
        ax.add_patch(box)
        ax.text(nx_pos, ny_pos, f"[Ext] {ext}", ha="center", va="center", fontsize=8, fontweight="bold", zorder=5)

    hosts_by_zone: Dict[str, List[Host]] = {z: [] for z in zone_boxes}
    for h in model.hosts.values():
        hosts_by_zone[h.zone].append(h)

    for z_id, h_list in hosts_by_zone.items():
        if not h_list:
            continue
        x, y, w, h, _, ec, _ = zone_boxes[z_id]
        cols = 2 if len(h_list) > 3 else 1
        rows = (len(h_list) + cols - 1) // cols
        usable_h = h - 5.5
        usable_w = w - 2.0

        for idx, host in enumerate(h_list):
            r = idx // cols
            c = idx % cols
            px = x + 1.0 + (c + 0.5) * (usable_w / cols)
            py = y + usable_h - (r + 0.5) * (usable_h / rows) + 1.0
            node_coords[host.id] = (px, py)

            ellipse = mpatches.FancyBboxPatch(
                (px - (usable_w / cols) * 0.44, py - 2.1),
                (usable_w / cols) * 0.88,
                4.2,
                boxstyle="round,pad=0.2,rounding_size=2.0",
                facecolor="#ffffff",
                edgecolor=ec,
                linewidth=1.4,
                zorder=4,
            )
            ax.add_patch(ellipse)

            ds_tag = f" [DS:{len(host.data_assets)}]" if host.data_assets else ""
            vuln_tag = f" !{len(host.vulnerabilities)}CVE" if host.vulnerabilities else ""
            ax.text(
                px,
                py,
                f"{host.id}: {host.name}\n({host.zone}){ds_tag}{vuln_tag}",
                ha="center",
                va="center",
                fontsize=7.2,
                fontweight="bold" if host.criticality >= 4 else "normal",
                zorder=5,
            )

    for flow in model.data_flows:
        if flow.src not in node_coords or flow.dst not in node_coords:
            continue
        x1, y1 = node_coords[flow.src]
        x2, y2 = node_coords[flow.dst]

        ax.annotate(
            "",
            xy=(x2, y2),
            xytext=(x1, y1),
            arrowprops=dict(
                arrowstyle="-|>",
                color="#1a237e",
                lw=1.3,
                connectionstyle="arc3,rad=0.12",
                shrinkA=14,
                shrinkB=14,
            ),
            zorder=6,
        )
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(
            mx,
            my + 0.8,
            f"{flow.id} ({flow.protocol})",
            fontsize=6.8,
            color="#1a237e",
            bbox=dict(boxstyle="round,pad=0.15", facecolor="white", edgecolor="#9fa8da", alpha=0.9),
            ha="center",
            zorder=7,
        )

    ax.set_title(
        "ACME Retail Ltd — Level-1 Data Flow Diagram (DFD) & Trust Boundaries",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    output_png.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(output_png)
    plt.close(fig)


def export_outputs(model: SystemModel, output_dir: str = "output") -> None:
    """Exporte la matrice d'atteignabilité (CSV + JSON) et le DFD PNG."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    reach_json_path = out / "reachability_matrix.json"
    with open(reach_json_path, "w", encoding="utf-8") as f:
        json.dump(model.reachability_matrix, f, indent=2)

    reach_csv_path = out / "reachability_matrix.csv"
    targets = list(model.hosts.keys())
    with open(reach_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["SRC \\ DST"] + targets)
        for src, row in model.reachability_matrix.items():
            cells = []
            for dst in targets:
                entries = row[dst]
                if not entries:
                    cells.append("-")
                else:
                    cells.append(";".join(f"{e['port']}/{e['service']}" for e in entries))
            writer.writerow([src] + cells)

    dfd_png_path = out / "dfd_level1.png"
    export_dfd_level1_png(model, dfd_png_path)


# ==============================================================================
# 7. POINT D'ENTRÉE CLI
# ==============================================================================

def main() -> int:
    json_file = sys.argv[1] if len(sys.argv) > 1 else "network.json"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"

    try:
        loader = NetworkLoader(json_file)
        model = loader.load_and_validate()
        export_outputs(model, output_dir)

        total_cves = sum(len(h.vulnerabilities) for h in model.hosts.values())
        total_mcs = sum(len(h.misconfigurations) for h in model.hosts.values())
        reachable_pairs = sum(
            1
            for src in model.reachability_matrix
            for dst in model.reachability_matrix[src]
            if model.reachability_matrix[src][dst]
        )

        print(f"[OK] Modèle validé : {model.metadata['name']} (v{model.metadata['version']})")
        print(f"     - Zones : {len(model.zones)} | Hôtes : {len(model.hosts)} | Entités externes : {len(model.external_entities)}")
        print(f"     - Vulnérabilités (CVE) : {total_cves} | Misconfigurations : {total_mcs}")
        print(f"     - Relations de confiance : {len(model.trust_relations)} | Flux de données : {len(model.data_flows)}")
        print(f"     - Paires atteignables (source -> cible) : {reachable_pairs}")
        print(f"     - Artefacts exportés dans : {os.path.abspath(output_dir)}")
        return 0

    except (FileNotFoundError, NetworkValidationError) as err:
        print(f"[ERREUR VALIDATION] {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
