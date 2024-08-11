# Cryptage/Décryptage AES - Application Tkinter

Une application Python avec une interface graphique Tkinter pour **crypter** et **décrypter** du texte à l'aide de l'algorithme AES (Advanced Encryption Standard).

A Python GUI application using Tkinter for **encrypting** and **decrypting** text with AES (Advanced Encryption Standard).

## Fonctionnalités / Features

- **Crypter** et **décrypter** du texte avec AES (clés de 128, 192, 256 bits).  
  **Encrypt** and **decrypt** text with AES (128, 192, 256-bit keys).
- **Modes de chiffrement** : CFB, CBC, GCM.  
  **Encryption modes**: CFB, CBC, GCM.
- **Charger** et **enregistrer** des fichiers texte (.txt).  
  **Load** and **save** text files (.txt).
- **Copier**, **coller**, et **effacer** du texte via l'interface.  
  **Copy**, **paste**, and **clear** text within the app.

## Prérequis / Requirements

- Python 3.x
- Tkinter (inclus avec Python)  
  Tkinter (comes with Python)
- Bibliothèque `cryptography`  
  `cryptography` library

## Installation / Setup Instructions

### Windows

1. Activez l'environnement / Activate the environment 


    ```bash
    Logiciel_env\Scripts\activate
    ```

### macOS/Linux

1. Activez l'environnement / Activate the environment 


    ```bash
    source Logiciel_env/bin/activate
    ```
2. Installation des Dépendances / Install Dependencies

Avec l'environnement virtuel activé, installez les dépendances nécessaires :

With the virtual environment active, install the required packages:

bash

pip install -r requirements.txt

Utilisation / How to Use

    Lancez l'application / Run the application:

    VBScript.vbs ou code.bat ou code.py

    Dans l'application / In the app:
        Entrez un code (mot de passe) pour générer la clé AES.
        Enter a code (password) to generate the AES key.
        Choisissez la méthode de chiffrement (AES-128, AES-192, AES-256) et le mode (CFB, CBC, GCM).
        Select the encryption method (AES-128, AES-192, AES-256) and mode (CFB, CBC, GCM).
        Chargez un fichier texte ou saisissez du texte dans la zone de texte.
        Load a text file or type text into the input area.
        Cryptez ou décryptez le texte.
        Encrypt or decrypt the text.
        Copiez, collez, ou effacez le texte selon vos besoins.
        Copy, paste, or clear the text as needed.

Remarques / Notes

    Conservez le code (mot de passe) utilisé pour le chiffrement. Il est nécessaire pour le décryptage.
    Remember your code (password) used for encryption—it is required for decryption.
    Le texte chiffré est encodé en base64 pour un stockage sécurisé.
    Encrypted text is base64 encoded for safe storage.

Auteur / Author

Développé par Cédric.P
Developed by Cédric.P
Licence / License

Ce projet est sous licence MIT.
