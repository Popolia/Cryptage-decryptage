Imports :

tkinter : module principal pour la création de l'interface graphique.
filedialog : pour ouvrir et enregistrer des fichiers.
messagebox : pour afficher des messages d'erreur.
cryptography : pour les opérations de chiffrement et de déchiffrement AES.
os : pour les opérations système.
pyperclip : pour copier du texte dans le presse-papiers.
secrets : pour générer des octets aléatoires.


Fonctions de chiffrement/déchiffrement :

generate_aes_key() : génère une clé AES avec un codage entropique.
aes_encrypt(key, plaintext) : chiffre le texte en clair avec AES.
aes_decrypt(key, ciphertext) : déchiffre le texte chiffré avec AES.
encrypt_aes(aes_key) : fonction d'interface pour le chiffrement AES.
decrypt_aes(aes_key) : fonction d'interface pour le déchiffrement AES.
clear_text() : efface le texte dans la zone de texte.
copy_to_clipboard() : copie le texte dans le presse-papiers.
charger_document() : charge un document à partir du disque.
enregistrer_document() : enregistre le document actuel sur le disque.


Interface utilisateur :

Fenêtre principale avec le titre "Criptage/Décriptage by Cédric P".
Cadre pour les boutons de chargement et d'enregistrement.
Boutons pour charger, enregistrer, crypter, décrypter, effacer et copier le texte.
Zone de texte pour afficher et saisir le texte.
Génération de la clé AES :

Une clé AES est générée au démarrage de l'application.


Boucle principale :

La boucle principale (root.mainloop()) est lancée pour exécuter l'interface graphique.


Si vous déplacez le dossier contenant votre projet vers un nouvel emplacement, il est généralement préférable de recréer l'environnement virtuel dans le nouveau chemin. Cela garantira que toutes les dépendances et configurations sont correctement configurées pour le nouvel emplacement.

Voici les étapes générales que vous pouvez suivre pour recréer l'environnement virtuel dans un nouvel emplacement :

Déplacez votre dossier de projet vers le nouvel emplacement.

Ouvrez un terminal ou une invite de commande et naviguez jusqu'au nouvel emplacement où vous avez déplacé votre projet.

Recréez l'environnement virtuel en utilisant la commande python -m venv nom_de_votre_environnement. Par exemple :

Copy code
python -m venv nouvel_env
Cela créera un nouvel environnement virtuel nommé "nouvel_env" dans le répertoire actuel.

Activez l'environnement virtuel nouvellement créé en exécutant la commande spécifique à votre système d'exploitation. Par exemple :

Sur Windows :
Copy code
.\nouvel_env\Scripts\activate
Sur macOS et Linux :
bash
Copy code
source nouvel_env/bin/activate
Une fois l'environnement virtuel activé, installez toutes les dépendances nécessaires pour votre projet à l'aide de pip install -r requirements.txt (si vous avez un fichier requirements.txt).

Avec l'environnement virtuel activé et toutes les dépendances installées, vous devriez pouvoir exécuter les commandes nécessaires pour votre projet, telles que l'exécution de PyInstaller pour créer des exécutables ou l'exécution de votre script Python.

En suivant ces étapes, vous devriez pouvoir déplacer votre projet vers un nouvel emplacement et recréer l'environnement virtuel sans rencontrer de problèmes majeurs.

pip install -r requirements.txt

tkinter = tk
