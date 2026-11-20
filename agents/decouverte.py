"""
Agent 1 : découverte des actifs.

Rôle : lire les logs et produire un inventaire des machines du réseau interne.
Pour chaque machine on veut savoir :
  - quels ports et services elle offre (ce qu'elle "sert" aux autres)
  - quels logiciels et versions elle utilise (pour l'agent 3 et les CVE)
  - avec qui elle parle et combien (pour l'agent 2 et la criticité)
  - si elle est joignable depuis l'extérieur (exposition)

Cet agent n'utilise PAS de LLM. Pourquoi : lire des logs et compter des
connexions doit être exact et rapide. Un LLM pourrait inventer des choses.

Deux sources possibles :
  1. Les logs Zeek (meilleure option, ils contiennent les versions des logiciels)
  2. Les CSV "TrafficLabelling" de CICIDS2017 (plus simple, mais sans versions)
"""

import ipaddress
import json
from collections import defaultdict
from pathlib import Path

import networkx as nx
import pandas as pd

import config

# États de connexion Zeek où le serveur n'a PAS répondu.
# Si le serveur ne répond pas, le port n'est pas vraiment "ouvert".
ETATS_SANS_REPONSE = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}

_RESEAU = ipaddress.ip_network(config.RESEAU_INTERNE)


# ---------------------------------------------------------------------------
# Outils de base
# ---------------------------------------------------------------------------

def vide(valeur) -> bool:
    """Vrai si la valeur est absente (None, NaN ou texte vide)."""
    return valeur is None or valeur == "" or (isinstance(valeur, float) and pd.isna(valeur))


def est_port_service(port) -> bool:
    """
    Vrai si le port peut correspondre à un vrai service.

    On exclut :
      - le port 0 (flux ICMP, comme le ping, qui n'ont pas de port)
      - les ports 32768 et plus : ports temporaires ouverts au vol
        par Linux (32768 et plus) et Windows (49152 et plus),
        pas des services durables
    """
    try:
        return 0 < int(port) < config.PORT_EPHEMERE_MIN
    except (TypeError, ValueError):
        return False


def est_interne(ip) -> bool:
    """Vrai si l'IP fait partie du réseau de l'organisation."""
    try:
        return ipaddress.ip_address(str(ip).strip()) in _RESEAU
    except ValueError:
        return False


def lire_log_zeek(chemin: Path) -> pd.DataFrame:
    """
    Lit un fichier log de Zeek et le transforme en tableau pandas.

    Zeek écrit ses logs en texte séparé par des tabulations. La ligne
    qui commence par "#fields" donne le nom des colonnes. Le caractère "-"
    veut dire "valeur absente". On gère aussi le format JSON de Zeek
    (une ligne JSON par événement), au cas où votre Zeek est configuré ainsi.
    """
    chemin = Path(chemin)
    if not chemin.exists():
        return pd.DataFrame()

    with open(chemin, encoding="utf-8", errors="replace") as f:
        premiere_ligne = f.readline()

    # Format JSON
    if premiere_ligne.lstrip().startswith("{"):
        return pd.read_json(chemin, lines=True)

    # Format texte (TSV) par défaut
    colonnes = None
    lignes = []
    with open(chemin, encoding="utf-8", errors="replace") as f:
        for ligne in f:
            ligne = ligne.rstrip("\n")
            if ligne.startswith("#fields"):
                colonnes = ligne.split("\t")[1:]
            elif ligne.startswith("#") or not ligne:
                continue
            else:
                lignes.append(ligne.split("\t"))

    if colonnes is None:
        return pd.DataFrame()

    df = pd.DataFrame(lignes, columns=colonnes)
    return df.replace({"-": None, "(empty)": None})


def _version_logiciel(ligne: pd.Series) -> str:
    """Reconstruit une version lisible (ex: 2.4.18) à partir de software.log."""
    morceaux = [ligne.get(c) for c in ("version.major", "version.minor", "version.minor2", "version.minor3")]
    morceaux = [str(m) for m in morceaux if not vide(m)]
    version = ".".join(morceaux)
    if not vide(ligne.get("version.addl")):
        version += f" ({ligne['version.addl']})"
    if version:
        return version
    return "inconnue" if vide(ligne.get("unparsed_version")) else ligne["unparsed_version"]


def _nouvel_actif(ip: str) -> dict:
    """Fiche vide pour une nouvelle machine découverte."""
    return {
        "ip": ip,
        "noms_dns": set(),
        "ports_ouverts": {},          # port -> {"protocole", "service", "connexions"}
        "logiciels": {},              # nom -> {"version", "type", "port"}
        "connexions_recues": 0,
        "connexions_emises": 0,
        "clients_uniques": set(),     # qui se connecte à cette machine
        "destinations_uniques": set(),  # à qui cette machine se connecte
        "clients_externes": set(),    # machines d'Internet qui se connectent à elle
        "indices_role": set(),
    }


# ---------------------------------------------------------------------------
# Source 1 : Zeek
# ---------------------------------------------------------------------------

def detecter_balayages(flux: pd.DataFrame) -> dict:
    """
    Repère les balayages de ports (scans).

    flux doit avoir les colonnes src, dst, port.
    Un utilisateur normal contacte quelques ports d'un serveur. Un scanner en
    teste des dizaines. Si une source touche au moins SEUIL_BALAYAGE ports
    différents sur une même destination, on considère que c'est un balayage.

    Renvoie {(source, destination): nombre de ports touchés}.
    """
    # On ne compte que les vrais ports de service. Les ports temporaires (32768 et
    # plus) changent à chaque connexion même en usage normal : par exemple, un
    # contrôleur de domaine Windows contacte chaque jour des dizaines de ports
    # temporaires différents sur les postes. Les compter le ferait passer pour un scanner.
    flux = flux[flux["port"].map(est_port_service)]
    ports_par_paire = flux.groupby(["src", "dst"])["port"].nunique()
    scans = ports_par_paire[ports_par_paire >= config.SEUIL_BALAYAGE]
    scans = {(src, dst): int(n) for (src, dst), n in scans.items()}

    # Répondre à un scanner n'est pas scanner.
    # Quand A scanne B, les CSV enregistrent parfois les réponses de B à l'envers
    # (B -> A), depuis ses ports de service. B semble alors scanner A.
    # Règle : si B -> A existe mais que A -> B touche encore plus de ports,
    # alors B ne fait que répondre, et on l'ignore.
    return {
        (src, dst): n for (src, dst), n in scans.items()
        if scans.get((dst, src), 0) <= n
    }


def _analyser_conn(conn: pd.DataFrame, actifs: dict, balayages: dict) -> None:
    """conn.log : qui parle à qui, sur quel port, avec quel service."""
    for _, c in conn.iterrows():
        src, dst = c.get("id.orig_h"), c.get("id.resp_h")
        port, proto = c.get("id.resp_p"), c.get("proto")
        service, etat = c.get("service"), c.get("conn_state")

        # La machine source émet une connexion
        if est_interne(src):
            a = actifs.setdefault(src, _nouvel_actif(src))
            a["connexions_emises"] += 1
            a["destinations_uniques"].add(dst)

        # La machine destination reçoit une connexion
        if est_interne(dst):
            a = actifs.setdefault(dst, _nouvel_actif(dst))
            a["connexions_recues"] += 1
            a["clients_uniques"].add(src)
            if not est_interne(src):
                a["clients_externes"].add(src)

            # Le port est considéré "ouvert" seulement si le serveur a répondu
            # et si la connexion ne fait pas partie d'un balayage
            if ((src, dst) not in balayages and etat not in ETATS_SANS_REPONSE
                    and est_port_service(port)):
                port = int(port)
                p = a["ports_ouverts"].setdefault(
                    port, {"protocole": proto, "service": None if vide(service) else service,
                           "connexions": 0}
                )
                p["connexions"] += 1
                if not vide(service) and vide(p["service"]):
                    p["service"] = service


def _analyser_software(software: pd.DataFrame, actifs: dict) -> None:
    """software.log : logiciels et versions détectés (bannières HTTP, SSH, ...)."""
    for _, s in software.iterrows():
        ip = s.get("host")
        if not est_interne(ip):
            continue
        # On ne garde que les logiciels "serveur" : ce sont eux qui sont exposés.
        # Les navigateurs (HTTP::BROWSER) des postes sont gardés aussi, ils peuvent
        # avoir des CVE, mais on note le type pour que l'agent 3 sache trier.
        a = actifs.setdefault(ip, _nouvel_actif(ip))
        nom = "inconnu" if vide(s.get("name")) else s["name"]
        a["logiciels"][nom] = {
            "version": _version_logiciel(s),
            "type": None if vide(s.get("software_type")) else s["software_type"],
            "port": None if vide(s.get("host_p")) else int(s["host_p"]),
        }


def _analyser_dns(dns: pd.DataFrame, actifs: dict) -> None:
    """dns.log : relie une IP à un nom (ex: 192.168.10.50 -> webserver.local)."""
    for _, d in dns.iterrows():
        nom, reponses = d.get("query"), d.get("answers")
        if vide(nom) or vide(reponses):
            continue
        reponses = reponses if isinstance(reponses, list) else str(reponses).split(",")
        for ip in reponses:
            ip = ip.strip()
            if est_interne(ip):
                actifs.setdefault(ip, _nouvel_actif(ip))["noms_dns"].add(nom)


def depuis_zeek(dossier: Path) -> tuple[dict, pd.DataFrame, dict]:
    """Construit l'inventaire à partir d'un dossier de logs Zeek."""
    dossier = Path(dossier)
    actifs: dict = {}

    conn = lire_log_zeek(dossier / "conn.log")
    if conn.empty:
        raise FileNotFoundError(f"Pas de conn.log utilisable dans {dossier}")

    # Tableau simplifié des connexions (graphe + détection des balayages)
    flux = conn.rename(columns={"id.orig_h": "src", "id.resp_h": "dst", "id.resp_p": "port"})
    flux = flux[["src", "dst", "port"]]
    balayages = detecter_balayages(flux)

    _analyser_conn(conn, actifs, balayages)
    _analyser_software(lire_log_zeek(dossier / "software.log"), actifs)
    _analyser_dns(lire_log_zeek(dossier / "dns.log"), actifs)
    return actifs, flux, balayages


# ---------------------------------------------------------------------------
# Source 2 : CSV CICIDS2017 (TrafficLabelling)
# ---------------------------------------------------------------------------

# Colonnes à échanger quand un flux est enregistré à l'envers
_PAIRES_A_ECHANGER = [
    ("Source IP", "Destination IP"),
    ("Source Port", "Destination Port"),
    ("Total Fwd Packets", "Total Backward Packets"),
    ("Total Length of Fwd Packets", "Total Length of Bwd Packets"),
]


def _remettre_dans_le_bon_sens(df: pd.DataFrame) -> pd.DataFrame:
    """
    Corrige les flux que CICFlowMeter (l'outil qui a créé les CSV) a enregistrés à l'envers.

    Il prend parfois la RÉPONSE d'un serveur pour une nouvelle connexion :
      normal  : poste (port 52000) -> Google (port 443)
      inversé : Google (port 443)  -> poste (port 52000)

    Un client ne part jamais d'un port en dessous de 1024 (ports réservés aux
    services). Donc un flux qui part d'un port < 1024 vers un port >= 1024 est
    une réponse à l'envers : on échange source et destination.
    """
    inverse = ((df["Source Port"] < config.PORT_SERVICE_RESERVE_MAX)
               & (df["Destination Port"] >= config.PORT_SERVICE_RESERVE_MAX))
    df = df.copy()
    for a, b in _PAIRES_A_ECHANGER:
        if a in df.columns and b in df.columns:
            valeurs_a = df.loc[inverse, a].copy()
            df.loc[inverse, a] = df.loc[inverse, b]
            df.loc[inverse, b] = valeurs_a
    return df


def depuis_csv(chemins: list[Path]) -> tuple[dict, pd.DataFrame, dict, dict]:
    """
    Construit l'inventaire à partir des CSV de flux de CICIDS2017.

    Moins riche que Zeek (pas de versions de logiciels), mais rapide.
    Renvoie aussi la "vérité terrain" : quelles machines ont été attaquées.
    """
    actifs: dict = {}
    attaques = defaultdict(lambda: defaultdict(int))
    morceaux = []

    for chemin in chemins:
        # latin-1 car certains fichiers CICIDS2017 contiennent des caractères mal encodés
        df = pd.read_csv(chemin, encoding="latin-1", low_memory=False)
        df.columns = df.columns.str.strip()  # les noms de colonnes commencent par un espace
        df = df.dropna(subset=["Source IP", "Destination IP"])
        df = _remettre_dans_le_bon_sens(df)
        morceaux.append(df)

    # On lit d'abord tous les fichiers, puis on repère les balayages sur l'ensemble
    tout = pd.concat(morceaux, ignore_index=True)
    flux = tout.rename(columns={"Source IP": "src", "Destination IP": "dst", "Destination Port": "port"})
    flux = flux[["src", "dst", "port"]]
    balayages = detecter_balayages(flux)

    for df in morceaux:
        for _, f in df.iterrows():
            src, dst = f["Source IP"], f["Destination IP"]
            port = int(f["Destination Port"])
            proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(int(f["Protocol"]), str(f["Protocol"]))

            if est_interne(src):
                a = actifs.setdefault(src, _nouvel_actif(src))
                a["connexions_emises"] += 1
                a["destinations_uniques"].add(dst)

            if est_interne(dst):
                a = actifs.setdefault(dst, _nouvel_actif(dst))
                a["connexions_recues"] += 1
                a["clients_uniques"].add(src)
                if not est_interne(src):
                    a["clients_externes"].add(src)
                # Le port est ouvert seulement si :
                #  - le serveur a renvoyé de vraies données (un port fermé répond
                #    aussi, par un paquet "refusé" RST, mais sans données)
                #  - et la connexion ne fait pas partie d'un balayage
                if ((src, dst) not in balayages
                        and f.get("Total Length of Bwd Packets", 0) > 0
                        and est_port_service(port)):
                    p = a["ports_ouverts"].setdefault(
                        port, {"protocole": proto, "service": None, "connexions": 0}
                    )
                    p["connexions"] += 1

                # \x96 est un tiret mal encodé dans les CSV d'origine
                label = str(f.get("Label", "BENIGN")).replace("\x96", "-").strip()
                if label != "BENIGN":
                    attaques[dst][label] += 1

    verite = {ip: dict(types) for ip, types in attaques.items()}
    return actifs, flux, verite, balayages


# ---------------------------------------------------------------------------
# Finition : indices de rôle, graphe, sauvegarde
# ---------------------------------------------------------------------------

def _ajouter_balayages(actifs: dict, balayages: dict) -> None:
    """Note dans la fiche de chaque machine qui l'a balayée."""
    for (src, dst), nb_ports in balayages.items():
        if dst in actifs:
            actifs[dst].setdefault("balayages_recus", []).append(
                {"source": src, "nb_ports": nb_ports, "source_externe": not est_interne(src)}
            )


def _ajouter_indices(actifs: dict) -> None:
    """Ajoute des indices de rôle à partir des ports ouverts."""
    for a in actifs.values():
        for port in a["ports_ouverts"]:
            if port in config.PORTS_INDICES:
                a["indices_role"].add(config.PORTS_INDICES[port])
        if not a["ports_ouverts"] and a["connexions_emises"] > 0:
            a["indices_role"].add("Aucun service offert : probablement un poste de travail")


def construire_graphe(flux: pd.DataFrame) -> nx.DiGraph:
    """
    Graphe des dépendances : une flèche A -> B veut dire "A utilise B".
    Le poids d'une flèche = nombre de connexions.
    On garde seulement les flux qui touchent au moins une machine interne.
    """
    flux = flux[flux["src"].map(est_interne) | flux["dst"].map(est_interne)]
    comptes = flux.groupby(["src", "dst"]).size().reset_index(name="poids")

    g = nx.DiGraph()
    for _, r in comptes.iterrows():
        for ip in (r["src"], r["dst"]):
            g.add_node(ip, interne=est_interne(ip))
        g.add_edge(r["src"], r["dst"], poids=int(r["poids"]))
    return g


def _vers_json(actifs: dict) -> list[dict]:
    """Transforme les ensembles (set) en listes, car JSON ne connaît pas les set."""
    sortie = []
    for a in actifs.values():
        sortie.append({
            "ip": a["ip"],
            "noms_dns": sorted(a["noms_dns"]),
            "ports_ouverts": [
                {"port": p, **infos} for p, infos in sorted(a["ports_ouverts"].items())
            ],
            "logiciels": [{"nom": n, **infos} for n, infos in a["logiciels"].items()],
            "connexions_recues": a["connexions_recues"],
            "connexions_emises": a["connexions_emises"],
            "nb_clients_uniques": len(a["clients_uniques"]),
            "nb_destinations_uniques": len(a["destinations_uniques"]),
            "expose_internet": len(a["clients_externes"]) > 0,
            "nb_clients_externes": len(a["clients_externes"]),
            "indices_role": sorted(a["indices_role"]),
            "balayages_recus": a.get("balayages_recus", []),
        })
    # Les machines les plus sollicitées en premier
    return sorted(sortie, key=lambda x: x["connexions_recues"], reverse=True)


def executer(dossier_zeek: Path | None = None, csvs: list[Path] | None = None,
             dossier_sortie: Path = config.DOSSIER_SORTIE) -> list[dict]:
    """
    Point d'entrée de l'agent 1.

    Écrit dans dossier_sortie :
      - inventaire.json      : la fiche de chaque actif (entrée de l'agent 2)
      - dependances.graphml  : le graphe (à ouvrir avec networkx, Gephi, pyvis)
      - dependances.csv      : le même graphe en tableau simple
      - balayages.json       : balayages de ports détectés
      - verite_terrain.json  : machines attaquées (CSV seulement)
    """
    dossier_sortie = Path(dossier_sortie)
    dossier_sortie.mkdir(parents=True, exist_ok=True)
    verite = None

    if dossier_zeek and (Path(dossier_zeek) / "conn.log").exists():
        actifs, flux, balayages = depuis_zeek(dossier_zeek)
        source = "Zeek"
    elif csvs:
        actifs, flux, verite, balayages = depuis_csv(csvs)
        source = "CSV CICIDS2017"
    else:
        raise FileNotFoundError("Aucune donnée : mettez des logs Zeek ou des CSV dans data/")

    # Si on a Zeek ET les CSV, on lit quand même les CSV pour la vérité terrain
    if source == "Zeek" and csvs:
        _, _, verite, _ = depuis_csv(csvs)

    _ajouter_balayages(actifs, balayages)
    _ajouter_indices(actifs)
    inventaire = _vers_json(actifs)
    graphe = construire_graphe(flux)

    with open(dossier_sortie / "inventaire.json", "w", encoding="utf-8") as f:
        json.dump(inventaire, f, indent=2, ensure_ascii=False)

    nx.write_graphml(graphe, dossier_sortie / "dependances.graphml")
    nx.to_pandas_edgelist(graphe).to_csv(dossier_sortie / "dependances.csv", index=False)

    # Les balayages sont une observation du trafic : les agents ont le droit de les voir
    liste_balayages = [
        {"source": s, "destination": d, "nb_ports": n}
        for (s, d), n in sorted(balayages.items(), key=lambda x: -x[1])
    ]
    with open(dossier_sortie / "balayages.json", "w", encoding="utf-8") as f:
        json.dump(liste_balayages, f, indent=2, ensure_ascii=False)

    # La vérité terrain est gardée À PART : les agents ne doivent pas la voir,
    # sinon ce serait de la triche. Elle sert seulement à évaluer le résultat final.
    if verite:
        with open(dossier_sortie / "verite_terrain.json", "w", encoding="utf-8") as f:
            json.dump(verite, f, indent=2, ensure_ascii=False)

    print(f"[Agent 1] Source : {source}")
    print(f"[Agent 1] {len(inventaire)} actifs internes découverts")
    print(f"[Agent 1] Graphe : {graphe.number_of_nodes()} machines, {graphe.number_of_edges()} liens")
    print(f"[Agent 1] {len(liste_balayages)} balayages de ports détectés")
    for b in liste_balayages[:5]:
        print(f"           {b['source']} -> {b['destination']} ({b['nb_ports']} ports)")
    return inventaire
