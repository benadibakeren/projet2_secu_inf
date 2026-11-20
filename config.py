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
