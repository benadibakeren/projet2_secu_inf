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
import re
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
    """
    Vrai si l'IP est une machine du réseau de l'organisation.

    On exclut l'adresse du réseau (.0) et l'adresse de diffusion (.255) :
    ce ne sont pas des machines, mais des adresses spéciales. Un message
    envoyé à .255 est reçu par tout le réseau.
    """
    try:
        adresse = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return (adresse in _RESEAU
            and adresse not in (_RESEAU.network_address, _RESEAU.broadcast_address))


def flux_ambigu(src, dst, port_src, port_dst, balayages: dict) -> bool:
    """
    Vrai si on ne peut pas se fier à ce flux pour dire qu'un port est ouvert.

    - il fait partie d'un balayage, dans un sens ou dans l'autre
      (quand A scanne B, les réponses de B vers A sont parfois enregistrées
      à l'envers et feraient croire que A a des centaines de ports ouverts)
    - les deux côtés utilisent le même port (ex. NetBIOS : 137 vers 137) :
      impossible de savoir lequel est le serveur
    """
    if (src, dst) in balayages or (dst, src) in balayages:
        return True
    try:
        return int(port_src) == int(port_dst)
    except (TypeError, ValueError):
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
        "clients_externes": set(),    # machines d'Internet qui utilisent un de ses services
        "ports_exposes": set(),       # ports de service utilisés depuis Internet
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
        port_src = c.get("id.orig_p")
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

            # Le port est considéré "ouvert" seulement si le serveur a répondu
            # et si le flux est fiable (pas un balayage, pas un même port des deux côtés)
            if (not flux_ambigu(src, dst, port_src, port, balayages)
                    and etat not in ETATS_SANS_REPONSE and est_port_service(port)):
                # Exposée à Internet = un de ses services est utilisé depuis l'extérieur
                if not est_interne(src):
                    a["clients_externes"].add(src)
                    a["ports_exposes"].add(int(port))
                port = int(port)
                p = a["ports_ouverts"].setdefault(
                    port, {"protocole": proto, "service": None if vide(service) else service,
                           "connexions": 0}
                )
                p["connexions"] += 1
                p.setdefault("clients", set()).add(src)
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


def _nom_compte(brut) -> tuple[str, str]:
    """
    Sépare un compte Kerberos ou NTLM en (nom, domaine).
    Kerberos écrit "alice/DOMAINE.LOCAL" ou "alice@DOMAINE.LOCAL".
    """
    if vide(brut):
        return "", ""
    brut = str(brut).strip()
    for separateur in ("/", "@", "\\"):
        if separateur in brut:
            nom, domaine = brut.split(separateur, 1)
            if separateur == "\\":
                nom, domaine = domaine, nom      # NTLM : DOMAINE\nom
            return nom.lower(), domaine.upper()
    return brut.lower(), ""


def _reussi(ligne: pd.Series) -> bool | None:
    """Zeek note la réussite dans "success" (T/F) ou, dans les vieilles versions, "status"."""
    v = ligne.get("success")
    if not vide(v):
        return str(v).strip().upper() in ("T", "TRUE", "1")
    v = ligne.get("status")
    if not vide(v):
        return "SUCCESS" in str(v).upper()
    return None


def lire_comptes(dossier: Path) -> dict:
    """
    Comptes vus dans les authentifications du réseau (journaux Zeek).

    - kerberos.log : authentifications auprès du contrôleur de domaine Active Directory
    - ntlm.log     : authentifications Windows plus anciennes (partages, RPC), avec le
                     nom de la machine cliente

    Renvoie {nom du compte: fiche}. Un compte dont le nom finit par "$" est un compte
    machine : c'est l'ordinateur lui-même qui s'authentifie, pas une personne.
    """
    comptes = {}

    def noter(nom, domaine, source, serveur, protocole, reussi, service=None):
        if not nom or not est_interne(source):
            return
        c = comptes.setdefault(nom, {
            "nom": nom, "domaine": domaine,
            "type": "machine" if nom.endswith("$") else "utilisateur",
            "privilege_probable": bool(re.search(r"admin|adm_|root", nom, re.I)),
            "machines_sources": set(), "serveurs": set(), "services": set(), "protocoles": set(),
            "authentifications": 0, "echecs": 0,
        })
        c["domaine"] = c["domaine"] or domaine
        c["machines_sources"].add(source)
        if est_interne(serveur):
            c["serveurs"].add(serveur)
        if service:
            c["services"].add(service)
        c["protocoles"].add(protocole)
        c["authentifications"] += 1
        if reussi is False:
            c["echecs"] += 1

    kerberos = lire_log_zeek(Path(dossier) / "kerberos.log")
    for _, k in kerberos.iterrows():
        nom, domaine = _nom_compte(k.get("client"))
        service = None if vide(k.get("service")) else str(k["service"])
        noter(nom, domaine, k.get("id.orig_h"), k.get("id.resp_h"), "Kerberos", _reussi(k), service)

    noms_machines = {}  # ntlm.log donne aussi le nom de la machine cliente
    ntlm = lire_log_zeek(Path(dossier) / "ntlm.log")
    for _, n in ntlm.iterrows():
        nom = "" if vide(n.get("username")) else str(n["username"]).lower()
        domaine = "" if vide(n.get("domainname")) else str(n["domainname"]).upper()
        noter(nom, domaine, n.get("id.orig_h"), n.get("id.resp_h"), "NTLM", _reussi(n))
        if not vide(n.get("hostname")) and est_interne(n.get("id.orig_h")):
            noms_machines.setdefault(n["id.orig_h"], set()).add(str(n["hostname"]).upper())

    return {"comptes": comptes, "noms_machines": noms_machines}


def enrichir_avec_zeek(actifs: dict, dossier: Path) -> dict:
    """
    Complète les machines découvertes dans les CSV avec ce que Zeek a vu :
    logiciels et versions (software.log), noms (dns.log, ntlm.log), comptes.
    On n'ajoute PAS de nouvelles machines : les CSV restent la source de l'inventaire.
    """
    dossier = Path(dossier)
    connues = set(actifs)
    temporaire = {}
    _analyser_software(lire_log_zeek(dossier / "software.log"), temporaire)
    _analyser_dns(lire_log_zeek(dossier / "dns.log"), temporaire)
    for ip, a in temporaire.items():
        if ip in connues:
            actifs[ip]["logiciels"].update(a["logiciels"])
            actifs[ip]["noms_dns"] |= a["noms_dns"]

    resultat = lire_comptes(dossier)
    for ip, noms in resultat["noms_machines"].items():
        if ip in connues:
            actifs[ip]["noms_dns"] |= noms
    for c in resultat["comptes"].values():
        for ip in c["machines_sources"] & connues:
            actifs[ip].setdefault("comptes_utilises", set()).add(c["nom"])
        for ip in c["serveurs"] & connues:
            actifs[ip].setdefault("comptes_servis", set()).add(c["nom"])
    return resultat["comptes"]


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
    attaques = defaultdict(lambda: defaultdict(int))         # attaques reçues
    attaques_emises = defaultdict(lambda: defaultdict(int))  # attaques envoyées par une machine interne
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
            port_src = int(f["Source Port"])
            proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(int(f["Protocol"]), str(f["Protocol"]))

            if est_interne(src):
                a = actifs.setdefault(src, _nouvel_actif(src))
                a["connexions_emises"] += 1
                a["destinations_uniques"].add(dst)

            if est_interne(dst):
                a = actifs.setdefault(dst, _nouvel_actif(dst))
                a["connexions_recues"] += 1
                a["clients_uniques"].add(src)
                # Le port est ouvert seulement si :
                #  - le serveur a renvoyé de vraies données (un port fermé répond
                #    aussi, par un paquet "refusé" RST, mais sans données)
                #  - et le flux est fiable (pas un balayage, pas un même port des deux côtés)
                if (not flux_ambigu(src, dst, port_src, port, balayages)
                        and f.get("Total Length of Bwd Packets", 0) > 0
                        and est_port_service(port)):
                    # Exposée à Internet = un de ses services est utilisé depuis l'extérieur
                    if not est_interne(src):
                        a["clients_externes"].add(src)
                        a["ports_exposes"].add(port)
                    p = a["ports_ouverts"].setdefault(
                        port, {"protocole": proto, "service": None, "connexions": 0}
                    )
                    p["connexions"] += 1
                    p.setdefault("clients", set()).add(src)

            # Vérité terrain. \x96 est un tiret mal encodé dans les CSV d'origine.
            # On note qui reçoit une attaque, mais aussi quelle machine interne en
            # envoie une : c'est le signe qu'elle a été compromise.
            label = str(f.get("Label", "BENIGN")).replace("\x96", "-").strip()
            if label != "BENIGN":
                if est_interne(dst):
                    attaques[dst][label] += 1
                if est_interne(src):
                    attaques_emises[src][label] += 1

    verite = {
        "recues": {ip: dict(types) for ip, types in attaques.items()},
        "emises": {ip: dict(types) for ip, types in attaques_emises.items()},
    }
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


def _est_vrai_service(port: int, infos: dict, ports_exposes: set) -> bool:
    """
    Un port compte comme service s'il a assez de connexions, et :
      1. au moins 2 clients différents (cas général),
      2. ou il est utilisé depuis Internet : derrière le pare-feu, tout Internet
         apparaît sous une seule adresse (traduction d'adresses, NAT),
      3. ou un seul client mais un usage massif : service dédié
         (ex : le contrôleur de domaine qui transmet ses requêtes DNS à la passerelle).
    """
    if infos["connexions"] < config.MIN_CONNEXIONS_SERVICE:
        return False
    return (len(infos.get("clients", ())) >= config.MIN_CLIENTS_SERVICE
            or port in ports_exposes
            or infos["connexions"] >= config.SEUIL_SERVICE_DEDIE)


def _retirer_ports_peu_utilises(actifs: dict) -> None:
    """
    Retire les ports vus trop rarement pour être de vrais services.

    Un service réel est utilisé plusieurs fois dans la journée, et par
    plusieurs machines. Un port vu 1 ou 2 fois, ou par un seul interlocuteur,
    est presque toujours un résidu (fin de scan, flux mal orienté) ou un
    échange particulier entre deux machines, pas un service rendu au réseau.
    C'est un compromis : on peut rater un service très rarement utilisé.
    """
    for a in actifs.values():
        a["ports_ouverts"] = {
            port: infos for port, infos in a["ports_ouverts"].items()
            if _est_vrai_service(port, infos, a["ports_exposes"])
        }
        a["ports_exposes"] &= set(a["ports_ouverts"])
        if not a["ports_exposes"]:
            a["clients_externes"] = set()


def _ajouter_indices(actifs: dict) -> None:
    """Ajoute des indices de rôle à partir des ports ouverts."""
    for a in actifs.values():
        for port in a["ports_ouverts"]:
            if port in config.PORTS_INDICES:
                a["indices_role"].add(config.PORTS_INDICES[port])
        if not a["ports_ouverts"] and a["connexions_emises"] > 0:
            a["indices_role"].add("Aucun service offert : probablement un poste de travail")
        # Par convention, la première adresse d'un réseau est souvent la passerelle
        if a["ip"] == str(_RESEAU.network_address + 1):
            a["indices_role"].add("Première adresse du réseau : souvent la passerelle (routeur ou pare-feu)")


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
                {"port": p, "protocole": infos["protocole"], "service": infos["service"],
                 "connexions": infos["connexions"], "nb_clients": len(infos.get("clients", ()))}
                for p, infos in sorted(a["ports_ouverts"].items())
            ],
            "logiciels": [{"nom": n, **infos} for n, infos in a["logiciels"].items()],
            "connexions_recues": a["connexions_recues"],
            "connexions_emises": a["connexions_emises"],
            "nb_clients_uniques": len(a["clients_uniques"]),
            "nb_destinations_uniques": len(a["destinations_uniques"]),
            "expose_internet": len(a["clients_externes"]) > 0,
            "nb_clients_externes": len(a["clients_externes"]),
            "ports_exposes": sorted(a["ports_exposes"]),
            "indices_role": sorted(a["indices_role"]),
            "balayages_recus": a.get("balayages_recus", []),
            # comptes qui s'authentifient DEPUIS cette machine (Zeek)
            "comptes_utilises": sorted(a.get("comptes_utilises", set())),
            # comptes qui s'authentifient AUPRÈS de cette machine (ex. contrôleur de domaine)
            "nb_comptes_servis": len(a.get("comptes_servis", set())),
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
      - comptes.json         : comptes vus dans les authentifications (si journaux Zeek)
      - verite_terrain.json  : machines attaquées (CSV seulement)
    """
    dossier_sortie = Path(dossier_sortie)
    dossier_sortie.mkdir(parents=True, exist_ok=True)
    verite = None

    # Les CSV sont la source principale des flux : toutes les règles de l'agent ont été
    # validées dessus. Zeek, s'il est présent, sert alors à ENRICHIR l'inventaire.
    zeek = Path(dossier_zeek) if dossier_zeek else None
    comptes = {}
    if csvs:
        actifs, flux, verite, balayages = depuis_csv(csvs)
        source = "CSV CICIDS2017"
        if zeek and zeek.is_dir() and any(zeek.glob("*.log")):
            comptes = enrichir_avec_zeek(actifs, zeek)
            source += " + enrichissement Zeek"
    elif zeek and (zeek / "conn.log").exists():
        actifs, flux, balayages = depuis_zeek(zeek)
        comptes = lire_comptes(zeek)["comptes"]
        source = "Zeek"
        for c in comptes.values():
            for ip in c["machines_sources"] & set(actifs):
                actifs[ip].setdefault("comptes_utilises", set()).add(c["nom"])
            for ip in c["serveurs"] & set(actifs):
                actifs[ip].setdefault("comptes_servis", set()).add(c["nom"])
    else:
        raise FileNotFoundError("Aucune donnée : mettez des logs Zeek ou des CSV dans data/")

    _ajouter_balayages(actifs, balayages)
    _retirer_ports_peu_utilises(actifs)
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

    # Comptes et relations compte -> machines (si Zeek a fourni kerberos.log / ntlm.log)
    liste_comptes = sorted((
        {**c, "machines_sources": sorted(c["machines_sources"]), "serveurs": sorted(c["serveurs"]),
         "services": sorted(c["services"])[:20], "protocoles": sorted(c["protocoles"])}
        for c in comptes.values()), key=lambda c: (c["type"] != "utilisateur", -c["authentifications"]))
    with open(dossier_sortie / "comptes.json", "w", encoding="utf-8") as f:
        json.dump(liste_comptes, f, indent=2, ensure_ascii=False)

    # La vérité terrain est gardée À PART : les agents ne doivent pas la voir,
    # sinon ce serait de la triche. Elle sert seulement à évaluer le résultat final.
    if verite:
        with open(dossier_sortie / "verite_terrain.json", "w", encoding="utf-8") as f:
            json.dump(verite, f, indent=2, ensure_ascii=False)

    print(f"[Agent 1] Source : {source}")
    print(f"[Agent 1] {len(inventaire)} actifs internes découverts")
    print(f"[Agent 1] Graphe : {graphe.number_of_nodes()} machines, {graphe.number_of_edges()} liens")
    utilisateurs = [c for c in liste_comptes if c["type"] == "utilisateur"]
    print(f"[Agent 1] Comptes : {len(utilisateurs)} utilisateurs, "
          f"{len(liste_comptes) - len(utilisateurs)} comptes machines"
          + ("" if liste_comptes else " (pas de kerberos.log ni ntlm.log)"))
    print(f"[Agent 1] {len(liste_balayages)} balayages de ports détectés")
    for b in liste_balayages[:5]:
        print(f"           {b['source']} -> {b['destination']} ({b['nb_ports']} ports)")
    return inventaire
