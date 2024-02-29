import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import pyperclip
import secrets


# Fonction pour générer une clé AES avec codage entropique
def generate_aes_key():
    # Générer des octets aléatoires supplémentaires pour renforcer l'entropie
    additional_entropy = secrets.token_bytes(16)
    
    # Clé AES générée aléatoirement
    aes_key = os.urandom(16)
    
    # Concaténer les octets aléatoires supplémentaires avec la clé AES
    aes_key_with_entropy = additional_entropy + aes_key
    
    return aes_key_with_entropy

# Fonction de cryptage AES
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

# Fonction de décryptage AES
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Fonction de l'interface utilisateur pour crypter avec AES
def encrypt_aes(aes_key):
    content = content_text.get('1.0', tk.END).encode('utf-8')  # Convertir en bytes avec UTF-8
    encrypted_content = aes_encrypt(aes_key, content)
    content_text.delete('1.0', tk.END)
    content_text.insert(tk.END, encrypted_content.hex())  # Afficher le texte crypté sous forme de chaîne hexadécimale

# Fonction de l'interface utilisateur pour décrypter avec AES
def decrypt_aes(aes_key):
    content = content_text.get('1.0', tk.END).strip()
    try:
        content = bytes.fromhex(content)
        decrypted_content = aes_decrypt(aes_key, content)
        original_text = decrypted_content.decode('utf-8')
        content_text.delete('1.0', tk.END)
        content_text.insert(tk.END, original_text)
    except ValueError:
        messagebox.showerror("Erreur", "Texte non valide.")

# Fonction pour effacer le texte
def clear_text():
    content_text.delete('1.0', tk.END)

# Fonction pour copier le texte dans le presse-papiers
def copy_to_clipboard():
    content = content_text.get('1.0', tk.END)
    pyperclip.copy(content)

# Fonction pour charger un document
def charger_document():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'r') as file:
            content_text.delete('1.0', tk.END)
            content_text.insert(tk.END, file.read())

# Fonction pour enregistrer le document
def enregistrer_document():
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'w') as file:
            content = content_text.get('1.0', tk.END)
            file.write(content)

# Création de la fenêtre principale
root = tk.Tk()
root.title("Criptage/Décriptage by Cédric P")

# Création du cadre pour les boutons de chargement et d'enregistrement
button_frame = tk.Frame(root)
button_frame.pack(side=tk.TOP, anchor="w")  # Alignement à gauche

# Bouton pour charger un document
load_button = tk.Button(button_frame, text="Charger", command=charger_document)
load_button.pack(side=tk.LEFT)

# Bouton pour enregistrer un document
save_button = tk.Button(button_frame, text="Enregistrer", command=enregistrer_document)
save_button.pack(side=tk.LEFT)

# Création de la zone de texte
content_text = tk.Text(root)
content_text.pack(expand=True, fill=tk.BOTH)

# Génération de la clé AES avec codage entropique
aes_key = generate_aes_key()

# Bouton pour crypter
encrypt_button = tk.Button(root, text="Crypter", command=lambda: encrypt_aes(aes_key))
encrypt_button.pack(side=tk.LEFT)

# Bouton pour décrypter
decrypt_button = tk.Button(root, text="Décrypter", command=lambda: decrypt_aes(aes_key))
decrypt_button.pack(side=tk.LEFT)

# Bouton pour effacer le texte
clear_button = tk.Button(root, text="Effacer texte", command=clear_text)
clear_button.pack(side=tk.RIGHT)

# Bouton pour copier le texte
copy_button = tk.Button(root, text="Copier texte", command=copy_to_clipboard)
copy_button.pack(side=tk.RIGHT)

# Lancement de la boucle principale
root.mainloop()
