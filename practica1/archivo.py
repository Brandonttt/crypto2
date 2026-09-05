import sys
import types

# ---------------------------------------------------------------------
# PARCHE DE COMPATIBILIDAD PARA PYTHON 3.13 (imghdr shim para pgpy)
# ---------------------------------------------------------------------
if "imghdr" not in sys.modules:
    imghdr_mock = types.ModuleType("imghdr")
    imghdr_mock.what = lambda *args, **kwargs: None
    sys.modules["imghdr"] = imghdr_mock

import os
import json
import base64
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog

# Librerías criptográficas
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

try:
    import pgpy
    PGPY_AVAILABLE = True
except Exception:
    PGPY_AVAILABLE = False


# =====================================================================
# 1. GESTOR DUAL DE CLAVES Y FIRMAS (PEM Y OPENPGP/.ASC)
# =====================================================================
class KeyAdapter:
    """Detecta y maneja indistintamente llaves RSA estándar (PEM) y OpenPGP (.asc)."""

    @staticmethod
    def load_private_key(raw_data: bytes, passphrase: str = None):
        """Devuelve una tupla: ('PEM'|'PGP', objeto_clave)"""
        text = raw_data.decode("utf-8", errors="ignore")

        # Caso A: Archivo OpenPGP (.asc con BEGIN PGP PRIVATE KEY)
        if "-----BEGIN PGP PRIVATE KEY" in text:
            if not PGPY_AVAILABLE:
                raise RuntimeError("El módulo pgpy no está disponible.")
            key, _ = pgpy.PGPKey.from_blob(text)
            if key.is_protected and passphrase:
                key.unlock(passphrase)
            return "PGP", key

        # Caso B: Archivo PEM / RSA tradicional (incluso si está guardado con extensión .asc)
        try:
            pwd = passphrase.encode('utf-8') if passphrase else None
            key = serialization.load_pem_private_key(raw_data, password=pwd, backend=default_backend())
            return "PEM", key
        except Exception as e:
            # Reintento si era OpenPGP sin encabezado estricto
            if PGPY_AVAILABLE:
                try:
                    key, _ = pgpy.PGPKey.from_blob(text)
                    if key.is_protected and passphrase:
                        key.unlock(passphrase)
                    return "PGP", key
                except Exception:
                    pass
            raise ValueError(f"No se pudo cargar la llave privada (ni como PEM ni como PGP): {e}")

    @staticmethod
    def load_public_key(raw_data: bytes):
        """Devuelve una tupla: ('PEM'|'PGP', objeto_clave, etiqueta_identidad)"""
        text = raw_data.decode("utf-8", errors="ignore")

        # Caso OpenPGP
        if "-----BEGIN PGP PUBLIC KEY" in text or ("PGP" in text and PGPY_AVAILABLE):
            try:
                key, _ = pgpy.PGPKey.from_blob(text)
                uids = ", ".join([str(u) for u in key.userids]) if key.userids else "Clave PGP"
                return "PGP", key, uids
            except Exception:
                pass

        # Caso PEM estándar
        try:
            key = serialization.load_pem_public_key(raw_data, backend=default_backend())
            return "PEM", key, "Clave Pública RSA (PEM)"
        except Exception:
            pass

        # Fallback a PGP si falló PEM
        if PGPY_AVAILABLE:
            try:
                key, _ = pgpy.PGPKey.from_blob(text)
                uids = ", ".join([str(u) for u in key.userids]) if key.userids else "Clave PGP"
                return "PGP", key, uids
            except Exception:
                pass

        raise ValueError("El formato de la llave pública no es un PEM ni un PGP (.asc) válido.")

    @staticmethod
    def sign_payload(key_type: str, priv_key, data: bytes, passphrase: str = None) -> dict:
        """Firma los bytes y devuelve dict con metadata del tipo de firma"""
        if key_type == "PGP":
            if priv_key.is_protected and passphrase:
                with priv_key.unlock(passphrase):
                    sig = priv_key.sign(data)
            else:
                sig = priv_key.sign(data)
            return {"type": "PGP", "signature": str(sig)}
        else:
            sig = priv_key.sign(
                data,
                asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return {"type": "PEM", "signature": base64.b64encode(sig).decode()}

    @staticmethod
    def verify_payload(key_type: str, pub_key, sig_data: dict, data: bytes) -> bool:
        """Verifica la firma según el formato almacenado"""
        try:
            sig_type = sig_data.get("type", key_type)
            if sig_type == "PGP":
                sig_obj = pgpy.PGPSignature.from_blob(sig_data["signature"])
                return bool(pub_key.verify(data, sig_obj))
            else:
                raw_sig = base64.b64decode(sig_data["signature"])
                pub_key.verify(
                    raw_sig,
                    data,
                    asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                return True
        except Exception:
            return False


# =====================================================================
# 2. MOTOR DIFFIE-HELLMAN Y AES-CBC
# =====================================================================
class CryptoEngine:
    DH_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    DH_G = 2

    @staticmethod
    def generate_dh_pair():
        priv = int.from_bytes(os.urandom(32), 'big')
        pub = pow(CryptoEngine.DH_G, priv, CryptoEngine.DH_P)
        return priv, pub

    @staticmethod
    def compute_dh_key(their_pub, my_priv, length=16):
        shared_int = pow(their_pub, my_priv, CryptoEngine.DH_P)
        shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(shared_bytes).digest()[:length]

    @staticmethod
    def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        return cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    @staticmethod
    def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


# =====================================================================
# 3. INTERFAZ GRÁFICA
# =====================================================================
class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Criptografía Híbrida - Soporte Dual (.pem / .asc)")
        self.geometry("980x760")

        self.priv_key_type = None
        self.loaded_priv_key = None
        self.priv_passphrase = None

        self.pub_key_type = None
        self.loaded_pub_key = None
        self.pub_key_label = "No cargada"

        self._init_ui()

    def _init_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_keys = ttk.Frame(notebook)
        self.tab_sender = ttk.Frame(notebook)
        self.tab_receiver = ttk.Frame(notebook)

        notebook.add(self.tab_keys, text="1. Gestión de Llaves (.pem / .asc)")
        notebook.add(self.tab_sender, text="2. Emisor: Alicia / Candy")
        notebook.add(self.tab_receiver, text="3. Receptor: Betito")

        self._build_tab_keys()
        self._build_tab_sender()
        self._build_tab_receiver()

    def _build_tab_keys(self):
        f = ttk.LabelFrame(self.tab_keys, text=" Carga o Generación de Identidad ", padding=15)
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="El sistema acepta cualquier llave privada o pública en formato .pem o .asc (PGP/RSA):").pack(anchor=tk.W, pady=5)
        
        btn_box = ttk.Frame(f)
        btn_box.pack(anchor=tk.W, pady=10)
        ttk.Button(btn_box, text="📂 Cargar Llave Privada (.pem o .asc)", command=self.action_load_priv).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_box, text="⚙ Generar Nueva RSA (PEM)", command=self.action_gen_rsa).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_box, text="💾 Exportar Clave Pública", command=self.action_export_pub).pack(side=tk.LEFT, padx=5)

        self.lbl_priv_status = ttk.Label(f, text="Llave Privada: No cargada", foreground="red", font=("Segoe UI", 9, "bold"))
        self.lbl_priv_status.pack(anchor=tk.W, pady=5)

        self.txt_key_details = scrolledtext.ScrolledText(f, height=18, font=("Consolas", 9))
        self.txt_key_details.pack(fill=tk.BOTH, expand=True, pady=10)

    def action_load_priv(self):
        path = filedialog.askopenfilename(filetypes=[("Claves Privadas", "*.pem;*.asc;*.key;*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()

            passphrase = None
            text = data.decode("utf-8", errors="ignore")
            if "ENCRYPTED" in text or ("PGP" in text and "BEGIN PGP PRIVATE KEY" in text):
                passphrase = simpledialog.askstring("Contraseña requerida", "Introduce la contraseña/passphrase de tu llave (deja vacío si no tiene):", show='*')

            ktype, key = KeyAdapter.load_private_key(data, passphrase)
            self.priv_key_type = ktype
            self.loaded_priv_key = key
            self.priv_passphrase = passphrase

            desc = f"Formato {ktype} detectado"
            if ktype == "PGP" and getattr(key, 'userids', None):
                desc += f" ({key.userids[0]})"
            self.lbl_priv_status.config(text=f"Llave Privada: Activa [{desc}]", foreground="green")

            self.txt_key_details.delete("1.0", tk.END)
            self.txt_key_details.insert(tk.END, f"[✓] Llave privada cargada con éxito.\nFormato: {ktype}\nArchivo: {os.path.basename(path)}\n\n")
            messagebox.showinfo("Éxito", f"Llave privada ({ktype}) lista para firmar.")
        except Exception as e:
            messagebox.showerror("Error de Llave", f"No se pudo cargar la llave privada:\n{e}")

    def action_gen_rsa(self):
        priv = rsa.generate_private_key(65537, 2048, default_backend())
        self.priv_key_type = "PEM"
        self.loaded_priv_key = priv
        self.priv_passphrase = None
        self.lbl_priv_status.config(text="Llave Privada: Nueva RSA 2048 generada en memoria", foreground="green")
        
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.txt_key_details.delete("1.0", tk.END)
        self.txt_key_details.insert(tk.END, "--- CLAVE PÚBLICA PEM ASOCIADA ---\n" + pub_pem)
        messagebox.showinfo("Generada", "Nueva clave generada.")

    def action_export_pub(self):
        if not self.loaded_priv_key:
            messagebox.showwarning("Aviso", "No hay llave activa.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("Archivos PEM/ASC", "*.pem;*.asc")])
        if path:
            if self.priv_key_type == "PEM":
                pub_bytes = self.loaded_priv_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
            else:
                pub_bytes = str(self.loaded_priv_key.pubkey).encode('utf-8')
            with open(path, "wb") as f:
                f.write(pub_bytes)
            messagebox.showinfo("Exportada", f"Clave guardada en: {path}")

    def _build_tab_sender(self):
        f = ttk.Frame(self.tab_sender, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        self.send_cipher = tk.BooleanVar(value=True)
        self.send_sign = tk.BooleanVar(value=True)

        opts = ttk.LabelFrame(f, text=" 1. Servicios a Ofrecer ", padding=10)
        opts.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(opts, text="Confidencialidad (Diffie-Hellman + AES-CBC)", variable=self.send_cipher).pack(side=tk.LEFT, padx=15)
        ttk.Checkbutton(opts, text="Firma Digital (Autenticación, Integridad y No Repudio)", variable=self.send_sign).pack(side=tk.LEFT, padx=15)

        msg_box = ttk.LabelFrame(f, text=" 2. Mensaje en Claro (m) ", padding=10)
        msg_box.pack(fill=tk.X, pady=5)
        self.txt_sender_msg = ttk.Entry(msg_box, font=("Segoe UI", 10))
        self.txt_sender_msg.insert(0, "Mensaje secreto de prueba para Betito.")
        self.txt_sender_msg.pack(fill=tk.X)

        ttk.Button(f, text="🔒 Ejecutar y Guardar Archivo Criptográfico para la Nube", command=self.action_send).pack(pady=10)

        log_box = ttk.LabelFrame(f, text=" Bitácora del Emisor ", padding=10)
        log_box.pack(fill=tk.BOTH, expand=True, pady=5)
        self.txt_sender_log = scrolledtext.ScrolledText(log_box, height=12, font=("Consolas", 9))
        self.txt_sender_log.pack(fill=tk.BOTH, expand=True)

    def action_send(self):
        self.txt_sender_log.delete("1.0", tk.END)
        do_c = self.send_cipher.get()
        do_s = self.send_sign.get()

        if not do_c and not do_s:
            messagebox.showwarning("Error", "Selecciona al menos un servicio.")
            return

        if do_s and not self.loaded_priv_key:
            messagebox.showerror("Error", "Carga tu llave privada (.pem o .asc) en la Pestaña 1 para firmar.")
            return

        msg_bytes = self.txt_sender_msg.get().strip().encode('utf-8')
        packet = {"cipher_active": do_c, "sign_active": do_s}

        # Confidencialidad
        if do_c:
            self.txt_sender_log.insert(tk.END, "[+] Servicio: CONFIDENCIALIDAD\n")
            a, Ka = CryptoEngine.generate_dh_pair()
            b, Kb = CryptoEngine.generate_dh_pair()
            k_session = CryptoEngine.compute_dh_key(Kb, a, 16)

            c, Kc = CryptoEngine.generate_dh_pair()
            d, Kd = CryptoEngine.generate_dh_pair()
            iv_session = CryptoEngine.compute_dh_key(Kd, c, 16)

            ciphertext = CryptoEngine.encrypt_aes_cbc(msg_bytes, k_session, iv_session)
            packet["dh_Ka"] = str(Ka)
            packet["dh_b_simulated"] = str(b)
            packet["dh_Kc"] = str(Kc)
            packet["dh_d_simulated"] = str(d)
            packet["payload"] = base64.b64encode(ciphertext).decode()
            self.txt_sender_log.insert(tk.END, f"    - Diffie-Hellman completado para K e IV.\n    - Cifrado AES-CBC generado ({len(ciphertext)} bytes).\n")
        else:
            packet["payload"] = base64.b64encode(msg_bytes).decode()
            self.txt_sender_log.insert(tk.END, "[i] Texto en claro sin cifrar.\n")

        # Firma
        if do_s:
            self.txt_sender_log.insert(tk.END, f"[+] Servicio: FIRMA DIGITAL ({self.priv_key_type})\n")
            sig_dict = KeyAdapter.sign_payload(self.priv_key_type, self.loaded_priv_key, msg_bytes, self.priv_passphrase)
            packet["sig_data"] = sig_dict
            self.txt_sender_log.insert(tk.END, "    - Hash SHA-256 generado y firmado con éxito.\n")

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Paquete JSON", "*.json;*.bin")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(packet, f, indent=2)
            self.txt_sender_log.insert(tk.END, f"\n[✓] Paquete guardado para la nube: {path}\n")
            messagebox.showinfo("Listo", "Archivo generado para subir a Google Drive.")

    def _build_tab_receiver(self):
        f = ttk.Frame(self.tab_receiver, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        load_box = ttk.LabelFrame(f, text=" 1. Archivo Descargado de la Nube (x, y, z) ", padding=10)
        load_box.pack(fill=tk.X, pady=5)
        ttk.Button(load_box, text="📂 Seleccionar Archivo Local", command=self.action_load_file).pack(side=tk.LEFT, padx=5)
        self.lbl_cloud_file = ttk.Label(load_box, text="Ningún archivo seleccionado", foreground="gray")
        self.lbl_cloud_file.pack(side=tk.LEFT, padx=10)

        web_box = ttk.LabelFrame(f, text=" 2. Llave Pública (.pem o .asc) ", padding=10)
        web_box.pack(fill=tk.X, pady=5)

        url_row = ttk.Frame(web_box)
        url_row.pack(fill=tk.X, pady=3)
        ttk.Label(url_row, text="URL Web:").pack(side=tk.LEFT, padx=5)
        self.txt_pub_url = ttk.Entry(url_row, width=50)
        self.txt_pub_url.insert(0, "https://gist.githubusercontent.com/.../raw/clave.asc")
        self.txt_pub_url.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(url_row, text="🌐 Descargar de la Web", command=self.action_download_web_pub).pack(side=tk.LEFT, padx=5)

        ttk.Button(web_box, text="📂 O cargar llave pública desde archivo local", command=self.action_load_local_pub).pack(anchor=tk.W, padx=5, pady=3)
        self.lbl_pub_status = ttk.Label(web_box, text="Llave pública: No cargada", foreground="red")
        self.lbl_pub_status.pack(anchor=tk.W, padx=5)

        ttk.Button(f, text="🔓 Descifrar y Verificar Autoría e Integridad", command=self.action_decrypt_verify).pack(pady=10)

        res_box = ttk.LabelFrame(f, text=" Resultados de Verificación y Contenido ", padding=10)
        res_box.pack(fill=tk.BOTH, expand=True, pady=5)
        self.txt_receiver_log = scrolledtext.ScrolledText(res_box, height=12, font=("Consolas", 9))
        self.txt_receiver_log.pack(fill=tk.BOTH, expand=True)

        self.loaded_packet = None

    def action_load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Paquetes", "*.json;*.bin;*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.loaded_packet = json.load(f)
                self.lbl_cloud_file.config(text=os.path.basename(path), foreground="black")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el archivo: {e}")

    def action_download_web_pub(self):
        url = self.txt_pub_url.get().strip()
        if not url:
            messagebox.showwarning("Error", "Introduce la URL de la llave pública.")
            return
        try:
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            ktype, pub_key, uids = KeyAdapter.load_public_key(r.content)
            self.pub_key_type = ktype
            self.loaded_pub_key = pub_key
            self.pub_key_label = uids
            self.lbl_pub_status.config(text=f"Llave web cargada [{ktype}]: {uids}", foreground="green")
            messagebox.showinfo("Éxito", f"Llave pública ({ktype}) descargada correctamente.")
        except Exception as e:
            messagebox.showerror("Error de Descarga Web", f"No se pudo procesar la llave desde la URL:\n{e}")

    def action_load_local_pub(self):
        path = filedialog.askopenfilename(filetypes=[("Llaves Públicas", "*.pem;*.asc;*.pub;*.*")])
        if path:
            try:
                with open(path, "rb") as f:
                    data = f.read()
                ktype, pub_key, uids = KeyAdapter.load_public_key(data)
                self.pub_key_type = ktype
                self.loaded_pub_key = pub_key
                self.pub_key_label = uids
                self.lbl_pub_status.config(text=f"Llave local cargada [{ktype}]: {uids}", foreground="green")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo cargar la llave pública:\n{e}")

    def action_decrypt_verify(self):
        self.txt_receiver_log.delete("1.0", tk.END)
        if not self.loaded_packet:
            messagebox.showwarning("Error", "Carga primero el archivo de la nube.")
            return

        p = self.loaded_packet
        payload_bytes = base64.b64decode(p["payload"])
        decrypted_m = None

        self.txt_receiver_log.insert(tk.END, "========================================================\n")
        self.txt_receiver_log.insert(tk.END, "           VERIFICACIÓN EN RECEPTOR (BETITO)            \n")
        self.txt_receiver_log.insert(tk.END, "========================================================\n")

        # 1. Descifrado
        if p.get("cipher_active", False):
            try:
                Ka = int(p["dh_Ka"])
                b = int(p["dh_b_simulated"])
                k_session = CryptoEngine.compute_dh_key(Ka, b, 16)

                Kc = int(p["dh_Kc"])
                d = int(p["dh_d_simulated"])
                iv_session = CryptoEngine.compute_dh_key(Kc, d, 16)

                decrypted_m = CryptoEngine.decrypt_aes_cbc(payload_bytes, k_session, iv_session)
                self.txt_receiver_log.insert(tk.END, "[✓] CONFIDENCIALIDAD: Descifrado Diffie-Hellman + AES exitoso.\n")
            except Exception as e:
                self.txt_receiver_log.insert(tk.END, f"[X] Error crítico al descifrar: {e}\n")
                messagebox.showerror("Fallo de Descifrado", "No se pudo descifrar el criptograma.")
                return
        else:
            decrypted_m = payload_bytes
            self.txt_receiver_log.insert(tk.END, "[i] Archivo en texto claro.\n")

        # 2. Verificación de Firma
        if p.get("sign_active", False):
            if not self.loaded_pub_key:
                messagebox.showwarning("Llave Faltante", "Descarga de la web la llave pública del autor.")
                return

            sig_data = p.get("sig_data", {})
            # Retrocompatibilidad con formato anterior si existía
            if not sig_data and "signature_asc" in p:
                sig_data = {"type": "PGP", "signature": p["signature_asc"]}

            is_valid = KeyAdapter.verify_payload(self.pub_key_type, self.loaded_pub_key, sig_data, decrypted_m)

            if is_valid:
                self.txt_receiver_log.insert(tk.END, "[✓] VERIFICACIÓN EXITOSA (Firma válida = )\n")
                self.txt_receiver_log.insert(tk.END, f"    ➔ AUTOR CONFIRMADO: {self.pub_key_label}\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ INTEGRIDAD: El mensaje no ha sido alterado.\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ NO REPUDIO: Vinculación estricta con el firmante.\n")
                messagebox.showinfo("Verificación Válida", f"Autor confirmado: {self.pub_key_label}\nIntegridad garantizada.")
            else:
                self.txt_receiver_log.insert(tk.END, "[X] VERIFICACIÓN FALLIDA (Firma inválida != )\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ ALERTA DE INTEGRIDAD: El mensaje fue alterado o la llave pública no es la del autor.\n")
                messagebox.showerror("Fallo de Verificación", "¡Alerta! La firma no coincide con la llave pública probada.")
        else:
            self.txt_receiver_log.insert(tk.END, "[i] Archivo sin firma digital.\n")

        self.txt_receiver_log.insert(tk.END, "\n--------------------------------------------------------\n")
        self.txt_receiver_log.insert(tk.END, f"CONTENIDO DEL MENSAJE:\n{decrypted_m.decode('utf-8', errors='replace')}\n")
        self.txt_receiver_log.insert(tk.END, "--------------------------------------------------------\n")


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()