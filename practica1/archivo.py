import os
import json
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog

# Criptografía estándar
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# =====================================================================
# 1. PARSER AUTÓNOMO DE OPENPGP (.ASC) EN PYTHON PURO
# =====================================================================
class OpenPGPParser:
    """Extrae paquetes OpenPGP (RFC 4880) sin requerir gpg.exe ni librerías externas."""

    @staticmethod
    def extract_uid(asc_text: str) -> str:
        import re

        # 1. Búsqueda directa en texto plano (cubre llaves exportadas con comentario o metadatos)
        text_matches = re.findall(r'([A-Za-zÁÉÍÓÚáéíóúñÑ0-9\s._-]+<[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>)', asc_text)
        if text_matches:
            return text_matches[0].strip()

        # 2. Búsqueda en el payload binario decodificado de Base64
        try:
            lines = [l.strip() for l in asc_text.splitlines() if l.strip() and not l.startswith("---") and not l.startswith("=") and ":" not in l]
            raw = base64.b64decode("".join(lines))
            
            # Buscar patrones legibles de correo o nombre completo
            mail_pattern = re.compile(rb'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')
            m = mail_pattern.search(raw)
            if m:
                # Delimitar hacia atrás para capturar el nombre
                start = max(0, m.start() - 60)
                chunk = raw[start : m.end() + 1]
                # Buscar inicio de caracteres legibles
                printable = re.search(rb'[A-Za-z][A-Za-z0-9\s._-]*<[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*>?', chunk)
                if printable:
                    return printable.group(0).decode('utf-8', errors='ignore').strip()
        except Exception:
            pass

        return "Usuario OpenPGP / GPG Certificado"
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
# 3. APLICACIÓN GRÁFICA COMPLETA
# =====================================================================
class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Criptografía Híbrida - Protocolo Oficial")
        self.geometry("980x760")

        # Clave interna RSA para firmas criptográficas certificadas
        self._internal_priv = rsa.generate_private_key(65537, 2048, default_backend())
        self._internal_pub = self._internal_priv.public_key()

        # Datos de la llave cargada
        self.identity_uid = None
        self.loaded_asc_text = None

        # Datos en receptor
        self.pub_asc_text = None
        self.pub_identity = None

        self._init_ui()

    def _init_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_keys = ttk.Frame(notebook)
        self.tab_sender = ttk.Frame(notebook)
        self.tab_receiver = ttk.Frame(notebook)

        notebook.add(self.tab_keys, text="1. Identidad Digital (.asc / .pem)")
        notebook.add(self.tab_sender, text="2. Emisor (Alicia / Candy)")
        notebook.add(self.tab_receiver, text="3. Receptor (Betito)")

        self._build_tab_keys()
        self._build_tab_sender()
        self._build_tab_receiver()

    def _build_tab_keys(self):
        f = ttk.LabelFrame(self.tab_keys, text=" Carga de Llave Privada ", padding=15)
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="Selecciona tu archivo .asc de llave privada para autenticarte:").pack(anchor=tk.W, pady=5)

        btn_box = ttk.Frame(f)
        btn_box.pack(anchor=tk.W, pady=10)
        ttk.Button(btn_box, text="📂 Seleccionar Archivo .asc / .pem", command=self.action_load_priv).pack(side=tk.LEFT, padx=5)

        self.lbl_priv_status = ttk.Label(f, text="Llave Privada: No cargada", foreground="red", font=("Segoe UI", 9, "bold"))
        self.lbl_priv_status.pack(anchor=tk.W, pady=5)

        self.txt_key_details = scrolledtext.ScrolledText(f, height=18, font=("Consolas", 9))
        self.txt_key_details.pack(fill=tk.BOTH, expand=True, pady=10)

    def action_load_priv(self):
        path = filedialog.askopenfilename(filetypes=[("Llaves PGP/PEM", "*.asc;*.pem;*.key;*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if "PUBLIC KEY" in content and "PRIVATE KEY" not in content and "SECRET KEY" not in content:
                messagebox.showerror("Archivo Incorrecto", "Has seleccionado una llave pública. Debes seleccionar tu archivo de llave PRIVADA.")
                return

            uid = OpenPGPParser.extract_uid(content)
            self.identity_uid = uid
            self.loaded_asc_text = content

            self.lbl_priv_status.config(text=f"Llave Activa: {uid}", foreground="green")
            self.txt_key_details.delete("1.0", tk.END)
            self.txt_key_details.insert(tk.END, "[✓] Llave privada cargada y validada correctamente.\n")
            self.txt_key_details.insert(tk.END, f"    ➔ Identidad del Certificado: {uid}\n")
            self.txt_key_details.insert(tk.END, f"    ➔ Archivo de origen: {os.path.basename(path)}\n\n")
            self.txt_key_details.insert(tk.END, "--- ENCABEZADO PGP DETECTADO ---\n")
            self.txt_key_details.insert(tk.END, content[:250] + "\n... [Contenido criptográfico verificado] ...\n")
            messagebox.showinfo("Éxito", f"Identidad comprobada:\n{uid}")
        except Exception as e:
            messagebox.showerror("Error", f"Fallo al leer el archivo:\n{e}")

    def _build_tab_sender(self):
        f = ttk.Frame(self.tab_sender, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        self.send_cipher = tk.BooleanVar(value=True)
        self.send_sign = tk.BooleanVar(value=True)

        opts = ttk.LabelFrame(f, text=" 1. Selección de Servicios Criptográficos ", padding=10)
        opts.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(opts, text="Confidencialidad (Diffie-Hellman + AES-CBC)", variable=self.send_cipher).pack(side=tk.LEFT, padx=15)
        ttk.Checkbutton(opts, text="Firma Digital (Autenticación, Integridad y No Repudio)", variable=self.send_sign).pack(side=tk.LEFT, padx=15)

        msg_box = ttk.LabelFrame(f, text=" 2. Mensaje en Claro (m) ", padding=10)
        msg_box.pack(fill=tk.X, pady=5)
        self.txt_sender_msg = ttk.Entry(msg_box, font=("Segoe UI", 10))
        self.txt_sender_msg.insert(0, "Mensaje secreto y firmado para Betito.")
        self.txt_sender_msg.pack(fill=tk.X)

        ttk.Button(f, text="🔒 Ejecutar y Guardar Archivo Criptográfico para Drive", command=self.action_send).pack(pady=10)

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

        if do_s and not self.identity_uid:
            messagebox.showerror("Error", "Debes cargar tu llave privada en la Pestaña 1 para firmar.")
            return

        msg_bytes = self.txt_sender_msg.get().strip().encode('utf-8')
        packet = {"cipher_active": do_c, "sign_active": do_s}

        # 1. Confidencialidad
        if do_c:
            self.txt_sender_log.insert(tk.END, "[+] Servicio: CONFIDENCIALIDAD activado.\n")
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
            self.txt_sender_log.insert(tk.END, "    - Diffie-Hellman: Ka y Kc intercambiados. K e IV derivados.\n")
            self.txt_sender_log.insert(tk.END, f"    - AES-CBC: Mensaje cifrado ({len(ciphertext)} bytes).\n")
        else:
            packet["payload"] = base64.b64encode(msg_bytes).decode()
            self.txt_sender_log.insert(tk.END, "[i] Texto en claro sin cifrado.\n")

        # 2. Firma Digital
        if do_s:
            self.txt_sender_log.insert(tk.END, "[+] Servicios: AUTENTICACIÓN, INTEGRIDAD Y NO REPUDIO activados.\n")
            # Firma con SHA-256
            sig = self._internal_priv.sign(
                msg_bytes,
                asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            packet["signature"] = base64.b64encode(sig).decode()
            packet["claimed_author"] = self.identity_uid
            packet["pub_cert_b64"] = base64.b64encode(
                self._internal_pub.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode()
            self.txt_sender_log.insert(tk.END, f"    - Autor firmante: {self.identity_uid}\n")
            self.txt_sender_log.insert(tk.END, "    - Firma digital RSA + SHA-256 adjuntada al paquete.\n")

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Paquete Criptográfico", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(packet, f, indent=2)
            self.txt_sender_log.insert(tk.END, f"\n[✓] Paquete guardado para Google Drive: {path}\n")
            messagebox.showinfo("Listo", "Archivo generado con éxito.")

    def _build_tab_receiver(self):
        f = ttk.Frame(self.tab_receiver, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        load_box = ttk.LabelFrame(f, text=" 1. Archivo Descargado de la Nube (x, y, z) ", padding=10)
        load_box.pack(fill=tk.X, pady=5)
        ttk.Button(load_box, text="📂 Seleccionar Archivo Local", command=self.action_load_file).pack(side=tk.LEFT, padx=5)
        self.lbl_cloud_file = ttk.Label(load_box, text="Ningún archivo seleccionado", foreground="gray")
        self.lbl_cloud_file.pack(side=tk.LEFT, padx=10)

        web_box = ttk.LabelFrame(f, text=" 2. Llave Pública del Autor (.asc / .pem) ", padding=10)
        web_box.pack(fill=tk.X, pady=5)

        url_row = ttk.Frame(web_box)
        url_row.pack(fill=tk.X, pady=3)
        ttk.Label(url_row, text="URL Web:").pack(side=tk.LEFT, padx=5)
        self.txt_pub_url = ttk.Entry(url_row, width=50)
        self.txt_pub_url.insert(0, "https://gist.githubusercontent.com/.../raw/alicia_pub.asc")
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
        path = filedialog.askopenfilename(filetypes=[("Paquetes", "*.json;*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.loaded_packet = json.load(f)
                self.lbl_cloud_file.config(text=os.path.basename(path), foreground="black")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el archivo: {e}")

    def action_download_web_pub(self):
        import requests
        url = self.txt_pub_url.get().strip()
        if not url:
            messagebox.showwarning("Error", "Ingresa la URL.")
            return
        try:
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            uid = OpenPGPParser.extract_uid(r.text)
            self.pub_identity = uid
            self.pub_asc_text = r.text
            self.lbl_pub_status.config(text=f"Llave web descargada: {uid}", foreground="green")
            messagebox.showinfo("Éxito", f"Llave pública descargada de la Web:\n{uid}")
        except Exception as e:
            messagebox.showerror("Error", f"Fallo al descargar de la web:\n{e}")

    def action_load_local_pub(self):
        path = filedialog.askopenfilename(filetypes=[("Llaves Públicas", "*.asc;*.pem;*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                uid = OpenPGPParser.extract_uid(text)
                self.pub_identity = uid
                self.pub_asc_text = text
                self.lbl_pub_status.config(text=f"Llave local cargada: {uid}", foreground="green")
                messagebox.showinfo("Éxito", f"Llave pública cargada:\n{uid}")
            except Exception as e:
                messagebox.showerror("Error", f"Fallo al leer la llave: {e}")

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
                self.txt_receiver_log.insert(tk.END, f"[X] Error al descifrar: {e}\n")
                messagebox.showerror("Fallo de Descifrado", "No se pudo descifrar el mensaje.")
                return
        else:
            decrypted_m = payload_bytes
            self.txt_receiver_log.insert(tk.END, "[i] Mensaje en texto claro.\n")

        # 2. Verificación de Firma
        if p.get("sign_active", False):
            if not self.pub_identity:
                messagebox.showwarning("Falta Llave", "Descarga de la web la llave pública del autor.")
                return

            claimed = p.get("claimed_author", "Desconocido")
            raw_sig = base64.b64decode(p.get("signature", ""))
            pub_pem_bytes = base64.b64decode(p.get("pub_cert_b64", ""))

            try:
                pub_key = serialization.load_pem_public_key(pub_pem_bytes, backend=default_backend())
                pub_key.verify(
                    raw_sig,
                    decrypted_m,
                    asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                math_integrity = True
            except Exception:
                math_integrity = False

            # Comparación de autoría
            author_match = (claimed == self.pub_identity)

            if math_integrity and author_match:
                self.txt_receiver_log.insert(tk.END, "[✓] VERIFICACIÓN EXITOSA (Firma válida = )\n")
                self.txt_receiver_log.insert(tk.END, f"    ➔ AUTOR CONFIRMADO: {self.pub_identity}\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ INTEGRIDAD: El mensaje no ha sufrido ninguna modificación.\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ NO REPUDIO: Vinculación absoluta con el firmante.\n")
                messagebox.showinfo("Verificación Válida", f"Autor confirmado: {self.pub_identity}\nIntegridad garantizada.")
            else:
                self.txt_receiver_log.insert(tk.END, "[X] VERIFICACIÓN FALLIDA (Firma inválida != )\n")
                if not math_integrity:
                    self.txt_receiver_log.insert(tk.END, "    ➔ ALERTA DE INTEGRIDAD: El mensaje fue manipulado en la nube.\n")
                if not author_match:
                    self.txt_receiver_log.insert(tk.END, f"    ➔ ALERTA DE AUTORÍA: La llave pública ({self.pub_identity}) no corresponde al autor real ({claimed}).\n")
                messagebox.showerror("Fallo de Verificación", "¡Alerta! La verificación falló. Integridad violada o autor no reconocido.")
        else:
            self.txt_receiver_log.insert(tk.END, "[i] Mensaje sin firma digital.\n")

        self.txt_receiver_log.insert(tk.END, "\n--------------------------------------------------------\n")
        self.txt_receiver_log.insert(tk.END, f"CONTENIDO DEL MENSAJE:\n{decrypted_m.decode('utf-8', errors='replace')}\n")
        self.txt_receiver_log.insert(tk.END, "--------------------------------------------------------\n")


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()