#!/usr/bin/env python3
"""
password_strength_checker.py
-----------------------------
Outil automatisé d'analyse de robustesse des mots de passe.

Fonctionnalités :
  - Vérifie si un mot de passe (ou une liste de mots de passe) figure
    dans un dictionnaire de mots de passe courants (ex: rockyou.txt).
  - Calcule un score de complexité (longueur, diversité de caractères, entropie).
  - Détecte des motifs faibles courants (séquences, répétitions, mots de passe
    "clavier" comme azerty/qwerty, etc.).
  - Peut être utilisé en CLI sur un seul mot de passe ou sur un fichier
    contenant une liste de mots de passe (un par ligne), par ex. un dump
    de hashes déjà crackés, pour un audit interne autorisé.

Usage :
  python password_strength_checker.py --password "MotDePasse123!"
  python password_strength_checker.py --file passwords.txt --wordlist rockyou.txt
  python password_strength_checker.py --wordlist rockyou.txt --password "123456"

Avertissement :
  Cet outil est destiné à des audits de sécurité autorisés (tests internes,
  sensibilisation, PFE/labo) sur des mots de passe que vous avez le droit
  d'analyser. Ne pas l'utiliser pour cracker des comptes sans autorisation.
"""

import argparse
import math
import re
import string
import sys
from pathlib import Path


# ----------------------------------------------------------------------
# Chargement du dictionnaire (ex: rockyou.txt)
# ----------------------------------------------------------------------
def load_wordlist(path: str) -> set:
    """Charge un dictionnaire de mots de passe dans un set pour recherche O(1).
    Le fichier rockyou.txt n'est pas inclus dans ce dépôt (trop volumineux,
    ~14M lignes) : téléchargez-le séparément et passez son chemin via --wordlist.
    """
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        print(f"[!] Dictionnaire introuvable : {path}", file=sys.stderr)
        sys.exit(1)

    words = set()
    with wordlist_path.open("r", encoding="latin-1", errors="ignore") as f:
        for line in f:
            words.add(line.strip())
    return words


# ----------------------------------------------------------------------
# Détection de motifs faibles
# ----------------------------------------------------------------------
KEYBOARD_PATTERNS = [
    "azertyuiop", "qwertyuiop", "qsdfghjklm", "asdfghjkl",
    "zxcvbnm", "wxcvbn", "1234567890", "0987654321",
]

COMMON_SUBSTRINGS = [
    "password", "motdepasse", "azerty", "qwerty", "123456",
    "admin", "welcome", "letmein", "iloveyou",
]


def has_keyboard_pattern(password: str) -> bool:
    lowered = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        for i in range(len(pattern) - 3):
            if pattern[i:i + 4] in lowered:
                return True
    return False


def has_sequential_chars(password: str, min_run: int = 4) -> bool:
    """Détecte des séquences croissantes/décroissantes (ex: abcd, 4321)."""
    run_up = run_down = 1
    for i in range(1, len(password)):
        if ord(password[i]) - ord(password[i - 1]) == 1:
            run_up += 1
            run_down = 1
        elif ord(password[i - 1]) - ord(password[i]) == 1:
            run_down += 1
            run_up = 1
        else:
            run_up = run_down = 1
        if run_up >= min_run or run_down >= min_run:
            return True
    return False


def has_repeated_chars(password: str, min_run: int = 4) -> bool:
    """Détecte des répétitions du même caractère (ex: aaaa, 1111)."""
    run = 1
    for i in range(1, len(password)):
        run = run + 1 if password[i] == password[i - 1] else 1
        if run >= min_run:
            return True
    return False


def contains_common_substring(password: str) -> bool:
    lowered = password.lower()
    return any(sub in lowered for sub in COMMON_SUBSTRINGS)


# ----------------------------------------------------------------------
# Calcul d'entropie approximative
# ----------------------------------------------------------------------
def estimate_charset_size(password: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    if any(c not in string.printable for c in password):
        size += 32  # marge pour caractères unicode/accentués
    return max(size, 1)


def estimate_entropy_bits(password: str) -> float:
    charset = estimate_charset_size(password)
    if not password:
        return 0.0
    return len(password) * math.log2(charset)


# ----------------------------------------------------------------------
# Analyse principale d'un mot de passe
# ----------------------------------------------------------------------
def analyze_password(password: str, wordlist: set | None = None) -> dict:
    report = {
        "password": password,
        "length": len(password),
        "entropy_bits": round(estimate_entropy_bits(password), 1),
        "in_wordlist": False,
        "issues": [],
        "score": 0,
    }

    if wordlist is not None and password in wordlist:
        report["in_wordlist"] = True
        report["issues"].append("Présent dans le dictionnaire de mots de passe courants")

    if len(password) < 8:
        report["issues"].append("Trop court (< 8 caractères)")
    if not re.search(r"[a-z]", password):
        report["issues"].append("Aucune minuscule")
    if not re.search(r"[A-Z]", password):
        report["issues"].append("Aucune majuscule")
    if not re.search(r"\d", password):
        report["issues"].append("Aucun chiffre")
    if not re.search(r"[^\w\s]", password):
        report["issues"].append("Aucun caractère spécial")
    if has_keyboard_pattern(password):
        report["issues"].append("Motif clavier détecté (ex: azerty, qwerty)")
    if has_sequential_chars(password):
        report["issues"].append("Séquence de caractères détectée (ex: abcd, 1234)")
    if has_repeated_chars(password):
        report["issues"].append("Caractères répétés détectés (ex: aaaa)")
    if contains_common_substring(password):
        report["issues"].append("Contient un mot-clé courant et faible")

    # Score simple sur 100, pénalisé par le nombre de problèmes et
    # bonifié par l'entropie estimée.
    score = min(report["entropy_bits"] / 0.6, 100)  # ~60 bits -> 100
    score -= len(report["issues"]) * 10
    if report["in_wordlist"]:
        score = 0
    report["score"] = max(0, round(score))

    if report["score"] >= 80:
        report["strength"] = "Fort"
    elif report["score"] >= 50:
        report["strength"] = "Moyen"
    else:
        report["strength"] = "Faible"

    return report


def print_report(report: dict) -> None:
    print(f"\nMot de passe : {report['password']}")
    print(f"  Longueur        : {report['length']}")
    print(f"  Entropie (bits) : {report['entropy_bits']}")
    print(f"  Dans dictionnaire : {'Oui' if report['in_wordlist'] else 'Non'}")
    print(f"  Score           : {report['score']}/100 ({report['strength']})")
    if report["issues"]:
        print("  Problèmes détectés :")
        for issue in report["issues"]:
            print(f"    - {issue}")
    else:
        print("  Aucun problème détecté.")


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Analyse la robustesse de mots de passe (audit autorisé uniquement)."
    )
    parser.add_argument("--password", help="Un mot de passe unique à analyser")
    parser.add_argument("--file", help="Fichier texte contenant un mot de passe par ligne")
    parser.add_argument(
        "--wordlist",
        help="Chemin vers un dictionnaire (ex: rockyou.txt) pour vérifier la présence du mot de passe",
    )
    args = parser.parse_args()

    if not args.password and not args.file:
        parser.error("Spécifiez --password ou --file")

    wordlist = load_wordlist(args.wordlist) if args.wordlist else None

    if args.password:
        report = analyze_password(args.password, wordlist)
        print_report(report)

    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] Fichier introuvable : {args.file}", file=sys.stderr)
            sys.exit(1)
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

        reports = [analyze_password(pw, wordlist) for pw in passwords]
        for r in reports:
            print_report(r)

        weak = sum(1 for r in reports if r["strength"] == "Faible")
        print(f"\nRésumé : {weak}/{len(reports)} mots de passe faibles.")


if __name__ == "__main__":
    main()