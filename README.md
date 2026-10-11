# Password Strength Checker

Outil Python en ligne de commande pour analyser la robustesse de mots de passe : détection de présence dans un dictionnaire (ex. `rockyou.txt`), calcul d'entropie, et détection de motifs faibles courants (séquences, répétitions, motifs clavier, mots-clés courants).

> ⚠️ **Avertissement** : cet outil est destiné à des audits de sécurité autorisés (tests internes, sensibilisation, labo/PFE) sur des mots de passe que vous avez le droit d'analyser. Ne l'utilisez pas pour tenter d'accéder à des comptes sans autorisation.

## Fonctionnalités

- Vérification de présence dans un dictionnaire de mots de passe courants (type `rockyou.txt`)
- Calcul d'un score de complexité basé sur la longueur, la diversité de caractères et l'entropie
- Détection de motifs faibles :
  - séquences de caractères (`abcd`, `1234`)
  - répétitions (`aaaa`, `1111`)
  - motifs clavier (`azerty`, `qwerty`)
  - mots-clés courants (`password`, `admin`, `welcome`, etc.)
- Analyse d'un mot de passe unique ou d'une liste complète via un fichier
- Résumé statistique (nombre de mots de passe faibles / total) pour une analyse en lot

## Prérequis

- Python 3.8 ou supérieur
- Aucune dépendance externe (uniquement la bibliothèque standard)

## Installation

```bash
git clone https://github.com/<ton-utilisateur>/password-strength-checker.git
cd password-strength-checker
```

### (Optionnel) Dictionnaire rockyou.txt

Le fichier `rockyou.txt` n'est **pas inclus** dans ce dépôt (trop volumineux, ~14 millions de lignes). Téléchargez-le séparément si vous souhaitez activer la vérification par dictionnaire, par exemple depuis un dépôt de wordlists SecLists, puis placez-le à la racine du projet ou indiquez son chemin via `--wordlist`.

Ajoutez-le à votre `.gitignore` si vous le gardez en local :

```
rockyou.txt
*.txt
!requirements.txt
```

## Utilisation

### Analyser un mot de passe unique

```bash
python password_strength_checker.py --password "MotDePasse123!"
```

### Analyser une liste de mots de passe depuis un fichier

Le fichier doit contenir un mot de passe par ligne :

```bash
python password_strength_checker.py --file passwords.txt
```

### Vérifier la présence dans un dictionnaire

```bash
python password_strength_checker.py --password "123456" --wordlist rockyou.txt
```

### Combiner fichier + dictionnaire

```bash
python password_strength_checker.py --file passwords.txt --wordlist rockyou.txt
```

## Exemple de sortie

```
Mot de passe : 123456
  Longueur        : 6
  Entropie (bits) : 19.9
  Dans dictionnaire : Oui
  Score           : 0/100 (Faible)
  Problèmes détectés :
    - Présent dans le dictionnaire de mots de passe courants
    - Trop court (< 8 caractères)
    - Aucune majuscule
    - Aucun caractère spécial
    - Séquence de caractères détectée (ex: abcd, 1234)
```

## Structure du projet

```
.
├── password_strength_checker.py   # Script principal
├── README.md                      # Ce fichier
└── passwords.txt                  # (optionnel) liste de mots de passe à analyser
```

## Pistes d'amélioration

- Export des résultats au format CSV/JSON
- Interface web simple (Flask) pour un usage non-CLI
- Intégration de règles NIST 800-63B pour le scoring
- Vérification via l'API [Have I Been Pwned](https://haveibeenpwned.com/API/v3) (k-anonymity)

## Auteur

Abdellah Esseidi — Étudiant ingénieur en cybersécurité (ENSA Tanger)

## Licence

MIT
