# Cryptage/Décryptage AES - Application Tkinter

Une application Python avec une interface graphique Tkinter pour **crypter** et **décrypter** du texte à l'aide de l'algorithme AES (Advanced Encryption Standard).

## Fonctionnalités

- **Chiffrement** et **déchiffrement** du texte avec AES (128, 192, 256 bits).
- **Modes de chiffrement** : CFB, CBC, GCM.
- **Charger** et **enregistrer** des fichiers texte (.txt).
- **Copier**, **coller**, et **effacer** du texte via l'interface.

## Prérequis

- Python 3.x
- Bibliothèque Tkinter (incluse avec Python)
- Bibliothèque `cryptography`

## Installation

### Windows

1. Activez l'environnement :

    ```bash
    Logiciel_env\Scripts\activate
    ```

### macOS/Linux

1. Créez un environnement virtuel :

    ```bash
    python3 -m venv Logiciel_env
    ```

2. Activez l'environnement :

    ```bash
    source Logiciel_env/bin/activate
    ```

### Installation des Dépendances

Avec l'environnement activé, installez les dépendances :

```bash
pip install -r requirements.txt

Utilisation

    Lancez l'application avec :

    bash

    python app.py

    Interface utilisateur :
        Entrez un code pour générer la clé AES.
        Choisissez la méthode (AES-128, AES-192, AES-256) et le mode (CFB, CBC, GCM).
        Chargez un fichier texte ou saisissez du texte.
        Cryptez ou décryptez le texte.
        Copiez, collez, ou effacez le texte.

Remarques

    Conservez le code (mot de passe) utilisé pour le chiffrement. Il est indispensable pour le décryptage.
    Le texte chiffré est encodé en base64.

Auteur

Développé par Cédric.P
Licence

Ce projet est sous licence MIT.
