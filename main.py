"""
Point d'entrée du projet : lance les agents dans l'ordre.

Utilisation :
    python main.py                  # tous les agents
    python main.py --depuis 2       # reprend à l'agent 2 (l'agent 1 a déjà tourné)
    python main.py --depuis 3       # seulement l'agent 3 (et les suivants)
    python main.py --sans-llm       # classification par règles seulement
    python main.py --zeek data/exemple --sortie output/exemple
"""

import argparse
from pathlib import Path

import config
from agents import classification, decouverte, vulnerabilites


def main():
    parser = argparse.ArgumentParser(description="Découverte des actifs et des vulnérabilités")
    parser.add_argument("--zeek", type=Path, default=config.DOSSIER_ZEEK,
                        help="Dossier contenant conn.log, software.log, dns.log")
    parser.add_argument("--csv", type=Path, default=config.DOSSIER_CSV,
                        help="Dossier contenant les CSV TrafficLabelling de CICIDS2017")
    parser.add_argument("--sortie", type=Path, default=config.DOSSIER_SORTIE)
    parser.add_argument("--depuis", type=int, default=1,
                        help="Numéro de l'agent par lequel commencer")
    parser.add_argument("--sans-llm", action="store_true",
                        help="Ne pas appeler le LLM (règles seulement)")
    args = parser.parse_args()

    # Agent 1 : découverte des actifs
    if args.depuis <= 1:
        csvs = sorted(args.csv.glob("*.csv")) if args.csv.exists() else []
        inventaire = decouverte.executer(args.zeek, csvs, args.sortie)

        print("\nTop 5 des actifs les plus sollicités :")
        for a in inventaire[:5]:
            ports = ", ".join(str(p["port"]) for p in a["ports_ouverts"][:8]) or "aucun"
            logiciels = ", ".join(f"{l['nom']} {l['version']}" for l in a["logiciels"]) or "aucun détecté"
            print(f"  {a['ip']:<16} ports: {ports:<25} logiciels: {logiciels}")
        print()

    # Agent 2 : classification (rôle + criticité)
    if args.depuis <= 2:
        classification.executer(args.sortie, utiliser_llm=not args.sans_llm)
        print()

    # Agent 3 : vulnérabilités (CVE, CVSS, KEV)
    if args.depuis <= 3:
        vulnerabilites.executer(args.sortie)
        print()

    # Agents 4 et 5 : à venir
    # risque.executer(...)
    # remediation.executer(...)


if __name__ == "__main__":
    main()
