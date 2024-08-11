import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding
import os
import base64

# Dictionnaire pour les traductions
LANGUAGES = {
    'fr': {
        'enter_code': "Entrez le code:",
        'choose_method': "Choisissez une méthode",
        'choose_mode': "Choisissez un mode",
        'encrypt': "Crypter",
        'decrypt': "Décrypter",
        'clear_text': "Effacer texte",
        'load': "Charger",
        'save': "Enregistrer",
        'copy_text': "Copier texte",
        'paste_text': "Coller texte",
        'error': "Erreur",
        'error_message': "Veuillez entrer un code, méthode et mode valides.",
        'decrypt_error': "Texte ou code non valide.",
        'clipboard_error': "Aucun texte valide dans le presse-papiers.",
        'method_tooltip': "AES-128 : Sécurité solide avec une clé de 128 bits.\nAES-192 : Sécurité renforcée avec une clé de 192 bits.\nAES-256 : Sécurité maximale avec une clé de 256 bits.",
        'mode_tooltip': "CFB : Adapté pour flux de données continus.\nCBC : Sécurisé pour chiffrement par blocs.\nGCM : Chiffrement et intégrité des données combinés."
    },
    'en': {
        'enter_code': "Enter code:",
        'choose_method': "Choose a method",
        'choose_mode': "Choose a mode",
        'encrypt': "Encrypt",
        'decrypt': "Decrypt",
        'clear_text': "Clear text",
        'load': "Load",
        'save': "Save",
        'copy_text': "Copy text",
        'paste_text': "Paste text",
        'error': "Error",
        'error_message': "Please enter a valid code, method, and mode.",
        'decrypt_error': "Invalid text or code.",
        'clipboard_error': "No valid text in the clipboard.",
        'method_tooltip': "AES-128: Solid security with a 128-bit key.\nAES-192: Enhanced security with a 192-bit key.\nAES-256: Maximum security with a 256-bit key.",
        'mode_tooltip': "CFB: Suitable for continuous data streams.\nCBC: Secure for block encryption.\nGCM: Encryption and data integrity combined."
    }
}

current_language = 'fr'  # Langue par défaut

# Fonction pour mettre à jour les textes en fonction de la langue sélectionnée
def update_texts():
    texts = LANGUAGES[current_language]
    code_label.config(text=texts['enter_code'])
    method_combobox.set(texts['choose_method'])
    mode_combobox.set(texts['choose_mode'])
    encrypt_button.config(text=texts['encrypt'])
    decrypt_button.config(text=texts['decrypt'])
    clear_button.config(text=texts['clear_text'])
    load_button.config(text=texts['load'])
    save_button.config(text=texts['save'])
    copy_button.config(text=texts['copy_text'])
    paste_button.config(text=texts['paste_text'])
    create_tooltip(method_combobox, texts['method_tooltip'])
    create_tooltip(mode_combobox, texts['mode_tooltip'])

def change_language(lang):
    global current_language
    current_language = lang
    update_texts()

# Fonction pour afficher des infobulles
def create_tooltip(widget, text):
    tooltip = tk.Toplevel(widget, bg='lightyellow', padx=1, pady=1)
    tooltip.withdraw()
    tooltip.overrideredirect(True)
    label = tk.Label(tooltip, text=text, bg='lightyellow', justify=tk.LEFT, relief=tk.SOLID, borderwidth=1)
    label.pack(ipadx=1)

    def enter(event):
        tooltip.geometry(f"+{widget.winfo_rootx() + 20}+{widget.winfo_rooty() + 20}")
        tooltip.deiconify()

    def leave(event):
        tooltip.withdraw()

    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)

# Fonction pour générer une clé AES basée sur un code utilisateur
def generate_aes_key_from_code(code, method):
    salt = b'static_salt_value'
    key_length = {
        "AES-128": 16,
        "AES-192": 24,
        "AES-256": 32
    }
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length[method],
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(code.encode('utf-8'))
    return key[:key_length[method]]

# Fonction de cryptage AES
def aes_encrypt(key, plaintext, mode):
    iv = os.urandom(16)
    cipher_modes = {
        "CFB": modes.CFB(iv),
        "CBC": modes.CBC(iv),
        "GCM": modes.GCM(iv)
    }

    cipher_mode = cipher_modes.get(mode)
    if cipher_mode is None:
        raise ValueError("Mode de chiffrement invalide")
    
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()

    if mode == "CBC":
        # Appliquer padding pour CBC
        padder = crypto_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext
    elif mode == "GCM":
        # Crypter avec GCM
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    else:
        # CFB
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

# Fonction de décryptage AES
def aes_decrypt(key, ciphertext, mode):
    iv = ciphertext[:16]
    cipher_modes = {
        "CFB": modes.CFB(iv),
        "CBC": modes.CBC(iv),
        "GCM": modes.GCM(iv)
    }

    cipher_mode = cipher_modes.get(mode)
    if cipher_mode is None:
        raise ValueError("Mode de déchiffrement invalide")

    if mode == "GCM":
        tag = ciphertext[16:32]
        ciphertext = ciphertext[32:]
        cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)
        except Exception as e:
            raise ValueError("Erreur de déchiffrement avec GCM: " + str(e))
        return plaintext
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        # Retirer padding pour CBC
        unpadder = crypto_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    else:
        # CFB
        cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        return plaintext

# Fonction de l'interface utilisateur pour crypter avec AES
def encrypt_aes():
    code = code_entry.get()
    method = method_combobox.get()
    mode = mode_combobox.get()
    if not code or method not in methods_list or mode not in mode_list:
        messagebox.showerror(LANGUAGES[current_language]['error'], LANGUAGES[current_language]['error_message'])
        return
    
    aes_key = generate_aes_key_from_code(code, method)
    content = content_text.get('1.0', tk.END).encode('utf-8')
    encrypted_content = aes_encrypt(aes_key, content, mode)
    content_text.delete('1.0', tk.END)
    content_text.insert(tk.END, base64.b64encode(encrypted_content).decode('utf-8'))

# Fonction de l'interface utilisateur pour décrypter avec AES
def decrypt_aes():
    code = code_entry.get()
    method = method_combobox.get()
    mode = mode_combobox.get()
    if not code or method not in methods_list or mode not in mode_list:
        messagebox.showerror(LANGUAGES[current_language]['error'], LANGUAGES[current_language]['error_message'])
        return
    
    aes_key = generate_aes_key_from_code(code, method)
    content = content_text.get('1.0', tk.END).strip()
    try:
        content = base64.b64decode(content)
        decrypted_content = aes_decrypt(aes_key, content, mode)
        original_text = decrypted_content.decode('utf-8')
        content_text.delete('1.0', tk.END)
        content_text.insert(tk.END, original_text)
    except (ValueError, base64.binascii.Error):
        messagebox.showerror(LANGUAGES[current_language]['error'], LANGUAGES[current_language]['decrypt_error'])

# Fonction pour effacer le texte
def clear_text():
    content_text.delete('1.0', tk.END)

# Fonction pour copier le texte dans le presse-papiers
def copy_to_clipboard():
    content = content_text.get('1.0', tk.END)
    root.clipboard_clear()
    root.clipboard_append(content)

# Fonction pour coller du texte depuis le presse-papiers
def paste_from_clipboard():
    try:
        content = root.clipboard_get()
        content_text.insert(tk.END, content)
    except tk.TclError:
        messagebox.showerror(LANGUAGES[current_language]['error'], LANGUAGES[current_language]['clipboard_error'])

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
root.title("Cryptage/Décryptage by Cédric.P")

# Création du menu pour la sélection de la langue
language_menu = tk.Menu(root)
root.config(menu=language_menu)
language_menu.add_command(label="Français", command=lambda: change_language('fr'))
language_menu.add_command(label="English", command=lambda: change_language('en'))

# Création des cadres pour organiser les éléments
input_frame = tk.Frame(root, padx=10, pady=10)
input_frame.pack(side=tk.TOP, fill=tk.X)

button_frame = tk.Frame(root, padx=10, pady=10)
button_frame.pack(side=tk.TOP, fill=tk.X)

clipboard_frame = tk.Frame(root, padx=10, pady=10)
clipboard_frame.pack(side=tk.TOP, fill=tk.X)

content_frame = tk.Frame(root, padx=10, pady=10)
content_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Zone d'entrée pour le code
code_label = tk.Label(input_frame, text=LANGUAGES[current_language]['enter_code'])
code_label.grid(row=0, column=0, sticky=tk.W)

code_entry = tk.Entry(input_frame)
code_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)

# Choix de la méthode de cryptage
methods_list = ["AES-128", "AES-192", "AES-256"]
method_combobox = ttk.Combobox(input_frame, values=methods_list)
method_combobox.set(LANGUAGES[current_language]['choose_method'])
method_combobox.grid(row=1, column=1, sticky=tk.EW, padx=5)

# Choix du mode d'opération
mode_list = ["CFB", "CBC", "GCM"]
mode_combobox = ttk.Combobox(input_frame, values=mode_list)
mode_combobox.set(LANGUAGES[current_language]['choose_mode'])
mode_combobox.grid(row=2, column=1, sticky=tk.EW, padx=5)

# Création des boutons de chargement et d'enregistrement
load_button = tk.Button(button_frame, text=LANGUAGES[current_language]['load'], command=charger_document)
load_button.pack(side=tk.LEFT, padx=5)

save_button = tk.Button(button_frame, text=LANGUAGES[current_language]['save'], command=enregistrer_document)
save_button.pack(side=tk.LEFT, padx=5)

# Boutons de copier et coller texte
copy_button = tk.Button(clipboard_frame, text=LANGUAGES[current_language]['copy_text'], command=copy_to_clipboard)
copy_button.pack(side=tk.LEFT, padx=5)

paste_button = tk.Button(clipboard_frame, text=LANGUAGES[current_language]['paste_text'], command=paste_from_clipboard)
paste_button.pack(side=tk.LEFT, padx=5)

# Création de la zone de texte
content_text = tk.Text(content_frame, wrap=tk.WORD)
content_text.pack(expand=True, fill=tk.BOTH)

# Boutons pour crypter, décrypter et effacer le texte
encrypt_button = tk.Button(button_frame, text=LANGUAGES[current_language]['encrypt'], command=encrypt_aes)
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = tk.Button(button_frame, text=LANGUAGES[current_language]['decrypt'], command=decrypt_aes)
decrypt_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(button_frame, text=LANGUAGES[current_language]['clear_text'], command=clear_text)
clear_button.pack(side=tk.LEFT, padx=5)

# Initialiser les infobulles
create_tooltip(method_combobox, LANGUAGES[current_language]['method_tooltip'])
create_tooltip(mode_combobox, LANGUAGES[current_language]['mode_tooltip'])

# Lancement de la boucle principale
root.mainloop()
