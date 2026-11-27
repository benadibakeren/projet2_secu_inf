"""
Agent 3 : association des actifs aux vulnérabilités connues (CVE).

Rôle : pour chaque actif, trouver les CVE de ses logiciels, avec
  - leur gravité (score CVSS de 0 à 10)
  - leur vecteur d'attaque (réseau = exploitable à distance, local = il faut déjà être sur la machine)
  - leur présence dans le catalogue CISA KEV (failles réellement exploitées par des attaquants)

D'où viennent les logiciels :
  1. L'inventaire déclaré (data/inventaire_declare.json), l'équivalent de la base
     d'inventaire (CMDB) d'une entreprise. Les flux CSV ne contiennent aucune version
     de logiciel : c'est donc la source principale.
  2. Les logiciels vus dans le trafic par Zeek (software.log), s'il a été lancé.

Cet agent n'utilise PAS de LLM : il interroge des bases officielles. Une CVE inventée
par un LLM serait une erreur grave dans un rapport de sécurité.

Il compare aussi l'inventaire déclaré et les machines découvertes sur le réseau :
une machine vue mais non déclarée, ou déclarée mais jamais vue, mérite une vérification.

Entrée  : output/actifs_classes.json   (agent 2)
Sorties : output/vulnerabilites.json, output/ecarts_inventaire.json
"""

import hashlib
import json
import os
import re
import time
from pathlib import Path

import requests

import config


# ---------------------------------------------------------------------------
# 1. Appels aux API, avec cache
# ---------------------------------------------------------------------------

class ClientNVD:
    """
    Interroge l'API NVD 2.0 en respectant ses limites de fréquence.

    Sans clé : 5 requêtes par 30 s, donc une pause de 6,5 s entre deux appels.
    Avec clé (gratuite) : 50 requêtes par 30 s.
    Chaque réponse est gardée en cache : le deuxième lancement est instantané.
    """

    def __init__(self, dossier_cache: Path = config.DOSSIER_CACHE):
        self.dossier_cache = Path(dossier_cache) / "nvd"
        self.dossier_cache.mkdir(parents=True, exist_ok=True)
        # .strip() retire les espaces et retours à la ligne collés par erreur avec
        # la clé : sinon requests refuse l'en-tête (erreur InvalidHeader).
        self.cle = (os.environ.get(config.NVD_VARIABLE_CLE) or "").strip() or None
        self.pause = 0.7 if self.cle else 6.5
        self.dernier_appel = 0.0
        self.hors_ligne = False  # passe à True après un échec complet
        self.session = requests.Session()
        if self.cle:
            self.session.headers["apiKey"] = self.cle

    def _attendre(self):
        attente = self.pause - (time.time() - self.dernier_appel)
        if attente > 0:
            time.sleep(attente)
        self.dernier_appel = time.time()

    def _requete(self, params: dict, essais: int = 4) -> dict:
        for essai in range(1, essais + 1):
            self._attendre()
            try:
                r = self.session.get(config.NVD_URL, params=params, timeout=60)
                if r.status_code == 200:
                    return r.json()
                # 403, 429, 503 : la NVD est surchargée ou on va trop vite
                print(f"[Agent 3]   NVD a répondu {r.status_code}, nouvel essai ({essai}/{essais})")
            except requests.RequestException as erreur:
                print(f"[Agent 3]   Erreur réseau ({type(erreur).__name__} : {str(erreur)[:120]}),"
                      f" nouvel essai ({essai}/{essais})")
            time.sleep(10 * essai)
        raise RuntimeError("NVD injoignable")

    def cves_du_logiciel(self, cpe: str) -> list[dict]:
        """
        Renvoie toutes les CVE qui touchent un logiciel.

        On utilise "virtualMatchString" : il accepte un début de nom CPE
        (ex. cpe:2.3:o:canonical:ubuntu_linux:16.04) et trouve toutes les
        variantes, ce qui évite de deviner le nom exact de la NVD.
        """
        fichier = self.dossier_cache / (hashlib.sha1(cpe.encode()).hexdigest()[:16] + ".json")
        if fichier.exists():
            return json.loads(fichier.read_text(encoding="utf-8"))["vulnerabilities"]
        # Si la NVD a déjà échoué complètement, on ne réessaie pas pour chaque
        # logiciel (sinon plusieurs minutes d'attente pour rien) : cache seulement.
        if self.hors_ligne:
            raise RuntimeError("NVD injoignable (mode hors ligne)")

        toutes, debut, total = [], 0, None
        while total is None or debut < total:
            try:
                page = self._requete({"virtualMatchString": cpe,
                                      "startIndex": debut, "resultsPerPage": 2000})
            except RuntimeError:
                self.hors_ligne = True
                print("[Agent 3]   NVD injoignable : passage en mode hors ligne (cache seulement)")
                raise
            total = page.get("totalResults", 0)
            toutes.extend(page.get("vulnerabilities", []))
            debut += page.get("resultsPerPage", 2000) or 2000
            if total > 2000:
                print(f"[Agent 3]   {min(debut, total)}/{total} CVE récupérées")

        fichier.write_text(json.dumps({"cpe": cpe, "vulnerabilities": toutes}), encoding="utf-8")
        return toutes


def charger_kev(dossier_cache: Path = config.DOSSIER_CACHE) -> dict:
    """
    Charge le catalogue CISA KEV : les CVE dont l'exploitation réelle est prouvée.
    Renvoie {identifiant CVE: informations}. Gardé en cache.
    """
    fichier = Path(dossier_cache) / "kev.json"
    if not fichier.exists():
        fichier.parent.mkdir(parents=True, exist_ok=True)
        r = requests.get(config.KEV_URL, timeout=60)
        r.raise_for_status()
        fichier.write_text(r.text, encoding="utf-8")
    catalogue = json.loads(fichier.read_text(encoding="utf-8"))
    return {
        v["cveID"]: {
            "ajoutee_le": v.get("dateAdded"),
            "rancongiciel": v.get("knownRansomwareCampaignUse") == "Known",
        }
        for v in catalogue.get("vulnerabilities", [])
    }


# ---------------------------------------------------------------------------
# 2. Lecture d'une CVE
# ---------------------------------------------------------------------------

def _score_cvss(metriques: dict) -> dict:
    """
    Récupère le score CVSS le plus récent disponible.

    Une CVE peut avoir plusieurs versions de CVSS (4.0, 3.1, 3.0, 2.0) et plusieurs
    sources. On prend la version la plus récente, et l'avis de la NVD ("Primary") en priorité.
    """
    for cle, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        liste = metriques.get(cle) or []
        if not liste:
            continue
        m = next((x for x in liste if x.get("type") == "Primary"), liste[0])
        donnees = m.get("cvssData", {})
        return {
            "score": donnees.get("baseScore"),
            "gravite": donnees.get("baseSeverity") or m.get("baseSeverity"),
            # CVSS 3 et 4 : attackVector ; CVSS 2 : accessVector
            "vecteur": donnees.get("attackVector") or donnees.get("accessVector"),
            "version_cvss": version,
        }
    return {"score": None, "gravite": None, "vecteur": None, "version_cvss": None}


def produits_vulnerables(cve: dict) -> list[str]:
    """
    Liste les produits que la NVD marque comme vulnérables (ex. "oracle jdk").

    On ignore les distributions (Ubuntu, Debian...) : la NVD les liste pour dire
    que le logiciel fautif est livré par elles, pas qu'elles sont le produit fautif.
    """
    produits = set()
    for configuration in cve.get("configurations", []):
        for noeud in configuration.get("nodes", []):
            for m in noeud.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                morceaux = m.get("criteria", "").split(":")
                if len(morceaux) <= 4 or morceaux[3] in config.EDITEURS_DISTRIBUTIONS:
                    continue
                nom = f"{morceaux[3]} {morceaux[4]}"
                if nom not in config.PRODUITS_DISTRIBUTIONS:
                    produits.add(nom)
    return sorted(produits)


def concerne_le_systeme(produits: list[str], cpe_logiciel: str) -> bool:
    """
    Vrai si la faille touche le système lui-même, pas un logiciel optionnel.

    - Windows : tout composant Microsoft (Internet Explorer, SMB...) fait partie du système.
    - Linux : le produit fautif doit être un paquet de base (noyau, bash, OpenSSL...).
    - Une application (Apache, OpenSSH...) : la faille la concerne toujours,
      puisqu'on l'a cherchée par son nom exact.
    - Aucun produit indiqué : on garde la faille, par prudence.
    """
    partie, editeur = cpe_logiciel.split(":")[2], cpe_logiciel.split(":")[3]
    if partie != "o" or not produits:
        return True
    for p in produits:
        vendeur, produit = p.split(" ", 1)
        if vendeur == editeur or produit in config.PAQUETS_DE_BASE_LINUX:
            return True
    return False


# Reconnaître les identifiants de bulletins dans les liens fournis par la NVD
_MOTIFS_BULLETINS = [
    (re.compile(r"\b(MS\d{2}-\d{3})\b", re.I), lambda m: m.group(1).upper()),           # Microsoft
    (re.compile(r"usn\.ubuntu\.com/(\d{3,5}-\d+)", re.I), lambda m: f"USN-{m.group(1)}"),  # Ubuntu
    (re.compile(r"\busn-(\d{3,5}-\d+)", re.I), lambda m: f"USN-{m.group(1)}"),             # Ubuntu
    (re.compile(r"\b(RHSA-\d{4}:\d{4,5})\b", re.I), lambda m: m.group(1).upper()),        # Red Hat
    (re.compile(r"\b(DSA-\d{3,5}(?:-\d+)?)\b", re.I), lambda m: m.group(1).upper()),      # Debian
    # Guide des mises à jour de Microsoft (remplace les bulletins MSxx-xxx depuis 2017)
    (re.compile(r"msrc\.microsoft\.com/.*?(CVE-\d{4}-\d{4,7})", re.I), lambda m: f"MSRC {m.group(1).upper()}"),
]
_EDITEURS = {"microsoft": "Microsoft", "ubuntu": "Ubuntu", "apache.org": "Apache",
             "openssh": "OpenSSH", "openbsd": "OpenSSH", "redhat": "Red Hat", "debian": "Debian"}


# Préfixe des bulletins publiés par l'éditeur de chaque système
PREFIXE_BULLETINS = {"microsoft": "MS", "canonical": "USN", "debian": "DSA", "redhat": "RHSA"}


def editeur_systeme(logiciels: list[dict]) -> str:
    """Éditeur du système d'exploitation de la machine (ex. "canonical" pour Ubuntu)."""
    for l in logiciels:
        morceaux = l["cpe"].split(":")
        if len(morceaux) > 3 and morceaux[2] == "o":
            return morceaux[3]
    return ""


def bulletins_securite(cve: dict, editeur_os: str = "", maximum: int = 4) -> list[dict]:
    """
    Bulletins de sécurité des éditeurs qui corrigent la CVE (ex. MS17-010 pour EternalBlue).

    La NVD donne pour chaque CVE une liste de liens, avec des étiquettes comme
    "Vendor Advisory" (bulletin de l'éditeur) ou "Patch" (correctif). On garde ces liens,
    et on en extrait l'identifiant du bulletin quand il est reconnaissable.
    """
    trouves, vus = [], set()
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        etiquettes = set(ref.get("tags") or [])
        identifiant = None
        for motif, former in _MOTIFS_BULLETINS:
            m = motif.search(url)
            if m:
                identifiant = former(m)
                break
        if not identifiant and not etiquettes & {"Vendor Advisory", "Patch"}:
            continue
        cle = identifiant or url
        if cle in vus:
            continue
        vus.add(cle)
        editeur = next((nom for cle_dom, nom in _EDITEURS.items() if cle_dom in url.lower()), "")
        trouves.append({"id": identifiant, "editeur": editeur, "url": url})
    # Les bulletins identifiés d'abord (ils parlent davantage à un administrateur)
    # Garder seulement les bulletins de l'éditeur du système de la machine :
    # un administrateur Ubuntu applique les USN, pas les bulletins Debian (DSA).
    attendu = PREFIXE_BULLETINS.get(editeur_os)
    if attendu:
        autres = tuple(p + "-" for p in PREFIXE_BULLETINS.values() if p != attendu)
        trouves = [b for b in trouves if not (b["id"] or "").startswith(autres)]
    # Bulletins connus que la NVD ne cite pas (voir config.BULLETINS_COMPLEMENTAIRES)
    for bid, info in config.BULLETINS_COMPLEMENTAIRES.items():
        if cve.get("id") in info["cves"] and bid not in vus:
            trouves.append({"id": bid, "editeur": "Microsoft", "url": info["url"], "source": "table locale"})
    # Les bulletins MSxx-xxx d'abord, puis les autres identifiés, puis les simples liens
    trouves.sort(key=lambda b: (b["id"] is None, not str(b["id"]).startswith(("MS0", "MS1"))))
    return trouves[:maximum]


def resumer_cve(brute: dict, kev: dict, cpe_logiciel: str = "", editeur_os: str = "") -> dict:
    """Garde l'essentiel d'une CVE renvoyée par la NVD."""
    cve = brute["cve"]
    produits = produits_vulnerables(cve)
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {
        "id": cve["id"],
        "publiee_le": (cve.get("published") or "")[:10],
        **_score_cvss(cve.get("metrics", {})),
        "dans_kev": cve["id"] in kev,
        "rancongiciel": kev.get(cve["id"], {}).get("rancongiciel", False),
        "produits": produits[:5],
        "concerne_le_systeme": concerne_le_systeme(produits, cpe_logiciel) if cpe_logiciel else True,
        "bulletins": bulletins_securite(cve, editeur_os),
        "description": description[:300],
    }


def _ordre_priorite(cve: dict):
    """Les CVE exploitées (KEV) d'abord, puis les plus graves."""
    return (not cve["dans_kev"], -(cve["score"] or 0))


# ---------------------------------------------------------------------------
# 3. Logiciels de chaque actif
# ---------------------------------------------------------------------------

def charger_inventaire_declare(chemin: Path = config.INVENTAIRE_DECLARE) -> dict:
    """Renvoie {ip: fiche déclarée}."""
    donnees = json.loads(Path(chemin).read_text(encoding="utf-8"))
    return {a["ip"]: a for a in donnees["actifs"]}


def logiciels_zeek(actif: dict) -> list[dict]:
    """
    Transforme les logiciels vus par Zeek en logiciels interrogeables dans la NVD.

    On ne garde que les logiciels serveur (type *SERVER) : ce sont eux que l'on
    peut attaquer à distance. Seule la partie numérique de la version est gardée
    (ex. "7.2 (p2 Ubuntu-4ubuntu2.1)" devient "7.2").
    """
    resultat = []
    for l in actif.get("logiciels", []):
        prefixe = config.CPE_LOGICIELS_ZEEK.get(l["nom"])
        if not prefixe or not str(l.get("type") or "").endswith("SERVER"):
            continue
        version = re.match(r"[\d.]+", str(l.get("version", "")))
        if not version:
            continue
        resultat.append({
            "nom": f"{l['nom']} {version.group(0).rstrip('.')}",
            "cpe": f"{prefixe}:{version.group(0).rstrip('.')}",
            "source": "vu dans le trafic (Zeek)",
            "ports": [l["port"]] if l.get("port") else [],
        })
    return resultat


def _produit(cpe: str) -> str:
    """Partie "éditeur:produit" d'un CPE (ex. apache:http_server), sans la version."""
    return ":".join(cpe.split(":")[3:5])


def logiciels_de(actif: dict, declare: dict) -> list[dict]:
    """
    Logiciels déclarés + logiciels vus dans le trafic par Zeek.

    Le trafic est plus fiable qu'une hypothèse :
      - même produit, même version : l'hypothèse est confirmée par le trafic
      - même produit, autre version : la version vue par Zeek remplace la déclarée
      - produit nouveau : il est ajouté
    """
    declares = [dict(l) for l in declare.get(actif["ip"], {}).get("logiciels", [])]
    for z in logiciels_zeek(actif):
        meme = next((l for l in declares if _produit(l["cpe"]) == _produit(z["cpe"])), None)
        if meme is None:
            declares.append(z)
        elif meme["cpe"] == z["cpe"]:
            meme["source"] = "inventaire déclaré, confirmé par le trafic (Zeek)"
        else:
            meme.update({"nom": z["nom"], "cpe": z["cpe"], "cpe_variantes": [],
                         "source": f"vu dans le trafic (Zeek), remplace la version déclarée ({meme['nom']})"})
    return declares


# ---------------------------------------------------------------------------
# 4. Analyse d'un actif
# ---------------------------------------------------------------------------

def analyser_logiciel(logiciel: dict, actif: dict, client: ClientNVD, kev: dict,
                      editeur_os: str = "") -> tuple[dict, list]:
    """Cherche les CVE d'un logiciel et renvoie (fiche du logiciel, liste des CVE)."""
    # La NVD range parfois les failles d'un même système sous plusieurs noms
    # (ex. windows_10 et windows_10_1607) : on interroge tous les noms, puis on
    # fusionne les résultats sans doublon.
    brutes, erreur, vues = [], None, set()
    for cpe in [logiciel["cpe"]] + logiciel.get("cpe_variantes", []):
        try:
            for b in client.cves_du_logiciel(cpe):
                if b["cve"]["id"] not in vues:
                    vues.add(b["cve"]["id"])
                    brutes.append(b)
        except RuntimeError as e:
            erreur = str(e)

    cves = [resumer_cve(b, kev, logiciel["cpe"], editeur_os) for b in brutes]
    if config.SEULEMENT_CVE_CONNUES_A_LA_CAPTURE:
        cves = [c for c in cves if c["publiee_le"] and c["publiee_le"] <= config.DATE_CAPTURE]
    # Failles de logiciels optionnels (Java, Firefox...) : comptées à part, puis écartées
    optionnelles = [c for c in cves if not c["concerne_le_systeme"]]
    if config.GARDER_SEULEMENT_PAQUETS_DE_BASE:
        cves = [c for c in cves if c["concerne_le_systeme"]]
    cves.sort(key=_ordre_priorite)

    # Exposé à Internet ? Un logiciel l'est si un de ses ports est utilisé depuis
    # Internet. Le système d'exploitation l'est si la machine a un port exposé.
    exposes = set(actif.get("ports_exposes", []))
    expose = bool(exposes & set(logiciel.get("ports", []))) if logiciel.get("ports") else bool(exposes)

    fiche = {
        "nom": logiciel["nom"],
        "cpe": logiciel["cpe"],
        "source": logiciel["source"],
        "ports": logiciel.get("ports", []),
        "expose_internet": expose,
        "nb_cve": len(cves),
        "nb_critiques": sum(1 for c in cves if (c["score"] or 0) >= 9),
        "nb_kev": sum(1 for c in cves if c["dans_kev"]),
        "nb_exploitables_a_distance": sum(1 for c in cves if c["vecteur"] in ("NETWORK", "ADJACENT_NETWORK")),
        "cvss_max": max((c["score"] or 0 for c in cves), default=0),
        "cves_prioritaires": cves[:config.NB_CVE_DETAILLEES],
        # Toutes les failles déjà exploitées (KEV), en version courte : elles servent à
        # choisir les correctifs à déployer, pas seulement les 10 plus graves.
        "cves_kev": [{"id": c["id"], "score": c["score"], "rancongiciel": c["rancongiciel"],
                      "bulletins": c["bulletins"]} for c in cves if c["dans_kev"]],
        "nb_cve_logiciels_optionnels_ecartees":
            len(optionnelles) if config.GARDER_SEULEMENT_PAQUETS_DE_BASE else 0,
        "logiciels_optionnels_les_plus_cites": _plus_cites(optionnelles),
        "erreur": erreur,
    }
    return fiche, cves


def _plus_cites(cves: list[dict], n: int = 5) -> list[str]:
    """Les produits optionnels qui reviennent le plus souvent (pour le rapport)."""
    compte = {}
    for c in cves:
        for p in c["produits"]:
            compte[p] = compte.get(p, 0) + 1
    return [f"{p} ({k})" for p, k in sorted(compte.items(), key=lambda x: -x[1])[:n]]


def analyser_actif(actif: dict, declare: dict, client: ClientNVD, kev: dict) -> dict:
    logiciels = logiciels_de(actif, declare)
    editeur_os = editeur_systeme(logiciels)
    fiches, toutes = [], {}
    for l in logiciels:
        print(f"[Agent 3] {actif['ip']:<16} {l['nom']}")
        fiche, cves = analyser_logiciel(l, actif, client, kev, editeur_os)
        fiches.append(fiche)
        for c in cves:  # une même CVE peut toucher le système et une application
            toutes[c["id"]] = c

    cves = list(toutes.values())
    resume = {
        "nb_cve": len(cves),
        "nb_critiques": sum(1 for c in cves if (c["score"] or 0) >= 9),
        "nb_kev": sum(1 for c in cves if c["dans_kev"]),
        "nb_exploitables_a_distance": sum(1 for c in cves if c["vecteur"] in ("NETWORK", "ADJACENT_NETWORK")),
        "cvss_max": max((c["score"] or 0 for c in cves), default=0),
        "logiciels_connus": bool(logiciels),
    }
    return {**actif, "logiciels_analyses": fiches, "resume_vulnerabilites": resume}


# ---------------------------------------------------------------------------
# 5. Comparaison inventaire déclaré / machines découvertes
# ---------------------------------------------------------------------------

def comparer_inventaires(actifs: list[dict], declare: dict) -> dict:
    """
    Compare ce qui est déclaré et ce qui est vu sur le réseau.

    - vu mais non déclaré : machine inconnue de l'organisation (oubli, appareil personnel, intrus)
    - déclaré mais jamais vu : machine éteinte, retirée, ou inventaire pas à jour
    """
    vus = {a["ip"] for a in actifs}
    return {
        "vus_mais_non_declares": sorted(vus - set(declare)),
        "declares_mais_non_vus": sorted(set(declare) - vus),
        "sans_logiciel_connu": sorted(ip for ip in vus & set(declare) if not declare[ip]["logiciels"]),
    }


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def executer(dossier_sortie: Path = config.DOSSIER_SORTIE) -> list[dict]:
    dossier_sortie = Path(dossier_sortie)
    actifs = json.loads((dossier_sortie / "actifs_classes.json").read_text(encoding="utf-8"))
    declare = charger_inventaire_declare()
    client = ClientNVD()

    try:
        kev = charger_kev()
        print(f"[Agent 3] Catalogue KEV chargé : {len(kev)} CVE exploitées connues")
    except requests.RequestException as e:
        print(f"[Agent 3] KEV injoignable ({type(e).__name__}) : on continue sans")
        kev = {}

    if not client.cle:
        print(f"[Agent 3] Pas de clé {config.NVD_VARIABLE_CLE} : appels lents (1 toutes les 6,5 s)")

    resultats = [analyser_actif(a, declare, client, kev) for a in actifs]
    resultats.sort(key=lambda a: (-a["resume_vulnerabilites"]["nb_kev"],
                                  -a["resume_vulnerabilites"]["cvss_max"]))

    ecarts = comparer_inventaires(actifs, declare)
    with open(dossier_sortie / "vulnerabilites.json", "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    with open(dossier_sortie / "ecarts_inventaire.json", "w", encoding="utf-8") as f:
        json.dump(ecarts, f, indent=2, ensure_ascii=False)

    filtre = f" (publiées avant le {config.DATE_CAPTURE})" if config.SEULEMENT_CVE_CONNUES_A_LA_CAPTURE else ""
    print(f"\n[Agent 3] Résumé{filtre} :")
    print(f"  {'IP':<16} {'CVE':>5} {'critiques':>9} {'KEV':>4} {'à distance':>10} {'CVSS max':>8}")
    for a in resultats:
        r = a["resume_vulnerabilites"]
        if not r["logiciels_connus"]:
            continue
        print(f"  {a['ip']:<16} {r['nb_cve']:>5} {r['nb_critiques']:>9} {r['nb_kev']:>4}"
              f" {r['nb_exploitables_a_distance']:>10} {r['cvss_max']:>8}")
    if ecarts["vus_mais_non_declares"]:
        print(f"[Agent 3] Vus sur le réseau mais non déclarés : {ecarts['vus_mais_non_declares']}")
    if ecarts["declares_mais_non_vus"]:
        print(f"[Agent 3] Déclarés mais jamais vus : {ecarts['declares_mais_non_vus']}")
    if ecarts["sans_logiciel_connu"]:
        print(f"[Agent 3] Sans logiciel connu (pas de recherche de CVE possible) : {ecarts['sans_logiciel_connu']}")
    return resultats
