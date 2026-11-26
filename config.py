"""
Configuration commune à tous les agents.

Pourquoi un fichier à part : si un chemin ou un réglage change,
on le modifie ici une seule fois, et tous les agents suivent.
"""

from pathlib import Path

# Dossier racine du projet (le dossier qui contient ce fichier)
RACINE = Path(__file__).resolve().parent

# Réseau interne de la victime dans CICIDS2017.
# Toute IP dans ce réseau est un "actif" de l'organisation.
# Les autres IP sont des machines externes (Internet, attaquants).
RESEAU_INTERNE = "192.168.10.0/24"

# Où se trouvent les données d'entrée
DOSSIER_ZEEK = RACINE / "data" / "zeek"   # sorties de Zeek (conn.log, software.log, ...)
DOSSIER_CSV = RACINE / "data" / "csv"     # CSV "TrafficLabelling" de CICIDS2017

# Où les agents écrivent leurs résultats
DOSSIER_SORTIE = RACINE / "output"

# Ports qui donnent un indice sur le rôle d'une machine.
# Ce ne sont que des indices : c'est l'agent de classification (agent 2)
# qui décidera du rôle final.
PORTS_INDICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "Web (HTTP)",
    88: "Kerberos (Active Directory)",
    135: "RPC Windows",
    139: "NetBIOS / partage Windows",
    389: "LDAP (Active Directory)",
    443: "Web (HTTPS)",
    445: "SMB (partage Windows)",
    636: "LDAPS (Active Directory)",
    1433: "Base de données SQL Server",
    3306: "Base de données MySQL",
    3389: "Bureau à distance (RDP)",
    5432: "Base de données PostgreSQL",
    8080: "Web (HTTP alternatif)",
}

# Ports temporaires (plage "éphémère") : le système les ouvre pour une seule
# connexion, ce ne sont pas des services. Linux commence à 32768, Windows à 49152.
# On prend la plus basse pour couvrir les deux.
PORT_EPHEMERE_MIN = 32768

# Détection des balayages de ports : si une machine touche au moins ce nombre
# de ports différents sur une même destination, c'est un scan, pas un usage normal.
SEUIL_BALAYAGE = 100

# Les ports en dessous de 1024 sont réservés aux services (80, 443, 53...).
# Un client ne part jamais d'un de ces ports : ça sert à repérer les flux
# que les CSV de CICIDS2017 ont enregistrés à l'envers.
PORT_SERVICE_RESERVE_MAX = 1024

# Un port doit être utilisé au moins ce nombre de fois pour compter comme service.
# En dessous, c'est presque toujours un résidu de scan ou un flux mal orienté.
MIN_CONNEXIONS_SERVICE = 5

# Un service est utilisé par au moins ce nombre de machines différentes.
# Une seule machine qui parle à une autre sur un port, ce n'est pas un service rendu au réseau.
MIN_CLIENTS_SERVICE = 2

# Exception : un seul client mais au moins ce nombre de connexions = service dédié.
# Exemple : le contrôleur de domaine transmet toutes ses requêtes DNS à la passerelle.
SEUIL_SERVICE_DEDIE = 500

# ---------------------------------------------------------------------------
# Agent 3 : vulnérabilités
# ---------------------------------------------------------------------------
# Inventaire déclaré de l'organisation (systèmes et logiciels installés)
INVENTAIRE_DECLARE = RACINE / "data" / "inventaire_declare.json"

# Cache des réponses NVD et KEV : on ne refait pas les mêmes appels à chaque lancement
DOSSIER_CACHE = RACINE / "cache"

# API officielles (gratuites)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Clé NVD facultative (gratuite) : 50 requêtes par 30 s au lieu de 5.
NVD_VARIABLE_CLE = "NVD_API_KEY"

# Date de la capture du trafic (jeudi de CICIDS2017).
# Si True, on ne garde que les CVE publiées avant cette date : on se place
# dans la situation de l'organisation à ce moment-là.
DATE_CAPTURE = "2017-07-06"
SEULEMENT_CVE_CONNUES_A_LA_CAPTURE = True

# Pour un système d'exploitation, la NVD rattache aussi les failles de logiciels
# optionnels distribués avec lui (Java, Firefox, Tomcat...), qui ne sont pas
# forcément installés. Si True, on ne garde que les failles du système lui-même.
GARDER_SEULEMENT_PAQUETS_DE_BASE = True

# Éditeurs de distributions : la NVD les liste comme "vulnérables" pour dire
# "ce logiciel est livré par cette distribution". Ils ne désignent pas le produit fautif.
EDITEURS_DISTRIBUTIONS = {"canonical", "debian", "redhat", "fedoraproject",
                          "opensuse", "suse", "novell", "oracle_linux"}

# Paquets présents sur toute installation Linux (base du système)
PAQUETS_DE_BASE_LINUX = {
    "linux_kernel", "bash", "glibc", "openssl", "sudo", "systemd", "util-linux",
    "coreutils", "shadow", "pam", "linux-pam", "polkit", "dbus", "openssh",
    "ntp", "apt", "dpkg", "libc", "gnutls", "libgcrypt", "zlib", "expat",
    "libxml2", "curl", "libcurl", "wget", "tar", "gzip", "bzip2", "xz", "procps",
    "cron", "rsyslog", "nss", "eglibc",
}

# Nombre de CVE détaillées par logiciel dans le fichier de sortie (les plus graves)
NB_CVE_DETAILLEES = 10

# Logiciels vus par Zeek : correspondance nom -> CPE (début du nom normalisé NVD)
CPE_LOGICIELS_ZEEK = {
    "Apache": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:f5:nginx",
    "OpenSSH": "cpe:2.3:a:openbsd:openssh",
    "Microsoft-IIS": "cpe:2.3:a:microsoft:internet_information_services",
    "vsftpd": "cpe:2.3:a:vsftpd_project:vsftpd",
    "ProFTPD": "cpe:2.3:a:proftpd:proftpd",
}

# ---------------------------------------------------------------------------
# LLM (agents 2 et 5)
# ---------------------------------------------------------------------------
# Groq et Ollama utilisent le même format que l'API OpenAI : on passe de l'un
# à l'autre en changeant seulement ces 3 lignes.

# Option 1 : Groq (gratuit, en ligne). La clé se met dans la variable GROQ_API_KEY.
LLM_URL = "https://api.groq.com/openai/v1"
LLM_MODELE = "openai/gpt-oss-120b"
LLM_VARIABLE_CLE = "GROQ_API_KEY"

# Option 2 : Ollama (gratuit, local). Décommenter ces 3 lignes et commenter celles du dessus.
# LLM_URL = "http://localhost:11434/v1"
# LLM_MODELE = "qwen2.5:3b"
# LLM_VARIABLE_CLE = None

# Rôles possibles pour un actif. Une liste fixe évite que le LLM invente
# un nom différent à chaque fois, ce qui rendrait les résultats impossibles à comparer.
ROLES_ACTIFS = [
    "Contrôleur de domaine",
    "Serveur web",
    "Serveur de base de données",
    "Serveur DNS",
    "Serveur de fichiers",
    "Serveur d'administration (SSH)",
    "Équipement réseau (pare-feu, routeur)",
    "Poste de travail",
    "Inconnu",
]
