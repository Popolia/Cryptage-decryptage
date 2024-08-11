# Cryptage/Décryptage AES - Application Tkinter

## Description

Cette application Python avec une interface graphique Tkinter permet de **crypter** et **décrypter** du texte en utilisant l'algorithme AES (Advanced Encryption Standard). Elle propose une interface conviviale pour charger, crypter, décrypter, copier, coller et enregistrer du texte.

### Fonctionnalités Principales

- **Charger** un fichier texte (.txt) pour le crypter ou le décrypter.
- **Enregistrer** le texte modifié dans un fichier .txt.
- **Crypter** le texte en utilisant un mot de passe, une méthode de chiffrement (AES-128, AES-192, AES-256) et un mode de chiffrement (CFB, CBC, GCM).
- **Décrypter** le texte chiffré avec les mêmes paramètres.
- **Effacer** le contenu de la zone de texte.
- **Copier** et **coller** du texte depuis ou vers le presse-papiers.

## Prérequis

- Python 3.x
- Bibliothèque Tkinter (incluse avec Python)
- Bibliothèque `cryptography` (pour le chiffrement AES)

## Installation

### 1. Créer et Activer un Environnement Virtuel

Il est recommandé d'utiliser un environnement virtuel pour gérer les dépendances :

#### Sous Windows

1. Ouvrez l'invite de commande.
2. Créez un environnement virtuel avec la commande suivante :

    ```bash
    python -m venv Logiciel_env
    ```

3. Activez l'environnement virtuel :

    ```bash
    Logiciel_env\Scripts\activate
    ```

#### Sous macOS/Linux

1. Ouvrez un terminal.
2. Créez un environnement virtuel avec la commande suivante :

    ```bash
    python3 -m venv Logiciel_env
    ```

3. Activez l'environnement virtuel :

    ```bash
    source Logiciel_env/bin/activate
    ```

### 2. Mise à Jour de `pip` (si nécessaire)

Si vous rencontrez des problèmes avec `pip`, mettez-le à jour :

```bash
pip install --upgrade pip

3. Installation des Dépendances

Avec l'environnement virtuel activé, installez les dépendances nécessaires :

bash

pip install -r requirements.txt

    Remarque : Assurez-vous d'exécuter cette commande dans le répertoire où se trouve requirements.txt.

Utilisation

    Clonez ce dépôt ou téléchargez le code source.

    Installez les dépendances comme indiqué ci-dessus.

    Exécutez le script principal pour démarrer l'application :

    bash

    python app.py

    Dans l'application :
        Entrez un code (mot de passe) pour générer la clé AES.
        Choisissez la méthode : AES-128, AES-192, ou AES-256.
        Sélectionnez le mode de chiffrement : CFB, CBC, ou GCM.
        Chargez un fichier texte ou saisissez du texte dans la zone de texte.
        Cryptez ou Décryptez le texte selon vos besoins.
        Copiez, collez, ou effacez le texte selon vos besoins.

Avertissements

    Mémorisez le code (mot de passe) utilisé pour le chiffrement. Il est indispensable pour déchiffrer le texte.
    Le texte chiffré est encodé en base64, mais reste sécurisé. Utilisez les mêmes paramètres pour le décryptage.

Auteur

Développé par Cédric.P

Licence

Ce projet est sous licence MIT. Vous êtes libre de l'utiliser, de le modifier, et de le distribuer. Cependant, l'auteur décline toute responsabilité quant à l'utilisation de ce logiciel.

