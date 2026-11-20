"""
Crée de petites données Zeek d'exemple dans data/exemple/.

Pourquoi : les vrais PCAP de CICIDS2017 pèsent plus de 10 Go. Avec ces
données minuscules (qui imitent le réseau de CICIDS2017), on peut tester
le code tout de suite, avant d'avoir téléchargé et traité les vraies données.

Utilisation :  python outils/creer_exemple.py
"""

import random
from pathlib import Path

DOSSIER = Path(__file__).resolve().parent.parent / "data" / "exemple"
random.seed(42)

# Quelques machines du réseau de CICIDS2017 (topologie publiée par l'UNB)
SERVEUR_WEB = "192.168.10.50"   # Ubuntu 16, Apache
SERVEUR_UB12 = "192.168.10.51"  # Ubuntu 12
CONTROLEUR = "192.168.10.3"     # Windows Server 2016, AD + DNS
POSTES = ["192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"]
ATTAQUANT = "205.174.165.73"    # Kali, externe


def ecrire_log(nom, champs, lignes):
    """Écrit un fichier au format texte de Zeek."""
    with open(DOSSIER / nom, "w", encoding="utf-8") as f:
        f.write("#separator \\x09\n")
        f.write(f"#path\t{nom[:-4]}\n")
        f.write("#fields\t" + "\t".join(champs) + "\n")
        for ligne in lignes:
            f.write("\t".join(str(v) for v in ligne) + "\n")
        f.write("#close\t2017-07-05-17-00-00\n")


def main():
    DOSSIER.mkdir(parents=True, exist_ok=True)
    champs = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "proto", "service", "conn_state"]
    conn = []
    n = 0

    def ajouter(src, dst, port, proto, service, etat="SF"):
        nonlocal n
        n += 1
        conn.append([1499256000 + n, f"C{n}", src, random.randint(40000, 60000),
                     dst, port, proto, service or "-", etat])

    # Les postes utilisent le DNS, l'AD et le serveur web
    for poste in POSTES:
        for _ in range(20):
            ajouter(poste, CONTROLEUR, 53, "udp", "dns")
        for _ in range(5):
            ajouter(poste, CONTROLEUR, 88, "tcp", "krb_tcp")
            ajouter(poste, CONTROLEUR, 389, "tcp", "ldap")
            ajouter(poste, CONTROLEUR, 445, "tcp", "smb")
        for _ in range(8):
            ajouter(poste, SERVEUR_WEB, 80, "tcp", "http")
        ajouter(poste, "8.8.8.8", 443, "tcp", "ssl")

    # Le serveur Ubuntu 12 est administré en SSH
    for _ in range(4):
        ajouter("192.168.10.9", SERVEUR_UB12, 22, "tcp", "ssh")

    # L'attaquant vise le serveur web (comme les attaques web du jeudi)
    for _ in range(30):
        ajouter(ATTAQUANT, SERVEUR_WEB, 80, "tcp", "http")
    # ... et fait un balayage de ports (beaucoup de ports fermés : état REJ)
    for port in range(1, 40):
        ajouter(ATTAQUANT, SERVEUR_WEB, port, "tcp", None, "REJ")
    ajouter(ATTAQUANT, SERVEUR_WEB, 22, "tcp", "ssh")

    ecrire_log("conn.log", champs, conn)

    # Logiciels détectés par Zeek (bannières des serveurs et navigateurs)
    ecrire_log("software.log",
               ["ts", "host", "host_p", "software_type", "name", "version.major",
                "version.minor", "version.minor2", "version.minor3", "version.addl", "unparsed_version"],
               [
                   [1499256000, SERVEUR_WEB, 80, "HTTP::SERVER", "Apache", 2, 4, 18, "-", "Ubuntu", "Apache/2.4.18 (Ubuntu)"],
                   [1499256000, SERVEUR_WEB, 22, "SSH::SERVER", "OpenSSH", 7, 2, "-", "-", "p2 Ubuntu-4ubuntu2.1", "OpenSSH_7.2p2"],
                   [1499256000, SERVEUR_UB12, 22, "SSH::SERVER", "OpenSSH", 5, 9, "-", "-", "p1 Debian-5ubuntu1", "OpenSSH_5.9p1"],
                   [1499256000, "192.168.10.5", "-", "HTTP::BROWSER", "Firefox", 54, 0, "-", "-", "-", "Firefox/54.0"],
               ])

    # Résolutions DNS
    ecrire_log("dns.log", ["ts", "uid", "query", "answers"], [
        [1499256000, "D1", "webserver.local", SERVEUR_WEB],
        [1499256000, "D2", "dc.local", CONTROLEUR],
    ])

    print(f"Données d'exemple créées dans {DOSSIER}")


if __name__ == "__main__":
    main()
