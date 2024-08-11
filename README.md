Cryptage/Décryptage AES - Application Tkinter
Description

Cette application GUI (interface graphique) en Python permet de crypter et décrypter des textes à l'aide de l'algorithme AES (Advanced Encryption Standard). Elle utilise l'interface Tkinter pour l'interaction avec l'utilisateur, offrant une interface simple pour charger, crypter, décrypter, copier, coller, et enregistrer du texte.

L'application supporte trois tailles de clé pour AES (128, 192 et 256 bits) et trois modes de chiffrement (CFB, CBC, GCM), chacun avec ses propres propriétés et niveaux de sécurité.
Fonctionnalités

    Charger un fichier texte (.txt) à crypter ou décrypter.
    Enregistrer le contenu actuel de la zone de texte dans un fichier .txt.
    Crypter le texte en utilisant un mot de passe, une méthode de chiffrement (AES-128, AES-192, AES-256) et un mode de chiffrement (CFB, CBC, GCM).
    Décrypter le texte chiffré en utilisant les mêmes paramètres que ceux utilisés pour le cryptage.
    Effacer le contenu de la zone de texte.
    Copier le contenu de la zone de texte dans le presse-papiers.
    Coller du texte depuis le presse-papiers dans la zone de texte.

Prérequis

    Python 3.x
    Bibliothèque Tkinter (installée par défaut avec Python)
    Bibliothèque cryptography pour le chiffrement AES

Installation des Prérequis
1. Création et activation de l'environnement virtuel

Il est recommandé d'utiliser un environnement virtuel pour isoler les dépendances de votre projet. Voici comment créer et activer un environnement virtuel :

Sous Windows :

bash

python -m venv Logiciel_env
Logiciel_env\Scripts\activate

Sous macOS/Linux :

bash

python3 -m venv Logiciel_env
source Logiciel_env/bin/activate

2. Mise à jour de pip dans l'environnement virtuel

Si vous ne pouvez pas utiliser Python correctement dans l'environnement virtuel, il est recommandé de mettre à jour pip :

Sous Windows :

bash

pip install --upgrade pip

Sous macOS/Linux :

bash

pip3 install --upgrade pip

3. Installation des dépendances

Une fois l'environnement virtuel activé et pip mis à jour, vous pouvez installer toutes les dépendances requises pour le projet en utilisant le fichier requirements.txt.

Exemple sous Windows :

bash

C:\Users\Admin\Documents\GitHub\Cryptage-decryptage\Logiciel_env> pip install -r requirements.txt

Exemple sous macOS/Linux :

bash

/path/to/your/project/Logiciel_env> pip install -r requirements.txt

Remarque

Le chemin exact vers votre dossier de projet peut varier. Assurez-vous d'exécuter la commande pip install -r requirements.txt dans le bon répertoire, là où se trouve votre fichier requirements.txt.
Utilisation

    Clonez ce dépôt ou téléchargez le code source.

    Assurez-vous que les dépendances sont installées.

    Exécutez le script Python (app.py ou main.py selon le nom de votre fichier).

    bash

    python app.py

    Dans l'interface utilisateur :
        Entrez un code (mot de passe) pour générer la clé AES.
        Sélectionnez la méthode (AES-128, AES-192, AES-256).
        Sélectionnez le mode de chiffrement (CFB, CBC, GCM).
        Chargez un fichier texte ou entrez du texte dans la zone de texte.
        Cliquez sur Crypter pour chiffrer le texte.
        Cliquez sur Décrypter pour déchiffrer le texte chiffré.
        Utilisez les boutons Copier, Coller, Effacer, Charger, et Enregistrer selon vos besoins.

Avertissements

    Assurez-vous de mémoriser ou de stocker de manière sécurisée le code (mot de passe) utilisé pour le chiffrement, car il est nécessaire pour déchiffrer les données.
    Le fichier texte chiffré est encodé en base64 pour le rendre lisible en texte brut, mais il est toujours chiffré et nécessite le même code, méthode, et mode pour être décrypté.

Auteur

    Cédric.P

Licence

Ce projet est sous licence MIT. Vous êtes libre de l'utiliser, de le modifier et de le distribuer à des fins personnelles ou commerciales. Cependant, l'auteur ne peut être tenu responsable des dommages résultant de l'utilisation de ce logiciel.