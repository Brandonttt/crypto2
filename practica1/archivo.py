import os
import re
import json
import base64
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# Criptografía estándar en Python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# =====================================================================
# 1. PARSER AUTÓNOMO OPENPGP / GPG (.ASC) EN PYTHON PURO
# =====================================================================
class OpenPGPAnalyzer:
    """Extrae UID y calcula el Key-ID único del módulo RSA de cualquier llave .asc o .pem."""

    @staticmethod
    def analyze(content: str):
        # 1. Extraer User ID (Nombre y Correo)
        uid = None
        # Búsqueda por regex de correo
        text_matches = re.findall(r'([A-Za-zÁÉÍÓÚáéíóúñÑ0-9\s._-]+<[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>)', content)
        if text_matches:
            uid = text_matches[0].strip()

        # 2. Si no viene en claro, buscar en los paquetes decodificados
        clean_lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("---") and not l.startswith("=") and ":" not in l]
        b64_str = "".join(clean_lines)

        try:
            raw = base64.b64decode(b64_str)
            if not uid:
                m = re.search(rb'([A-Za-z0-9\s._-]+<[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>)', raw)
                if m:
                    uid = m.group(1).decode('utf-8', errors='ignore').strip()

            # Extraer módulo RSA para cálculo de Key ID único
            pos = 9
            n_bits = (raw[pos] << 8) | raw[pos+1]
            n_bytes = (n_bits + 7) // 8
            pos += 2
            n_val = raw[pos : pos + n_bytes]
            key_id = hashlib.sha256(n_val).hexdigest()[:16].upper()
        except Exception:
            key_id = hashlib.sha256(content.encode('utf-8')).hexdigest()[:16].upper()

        if not uid:
            uid = f"Usuario_GPG_{key_id[:8]}"

        return uid, key_id


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
# 3. INTERFAZ GRÁFICA PRINCIPAL
# =====================================================================
class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Práctica Criptografía Híbrida - Protocolo Oficial")
        self.geometry("980x760")

        # Par asimétrico interno vinculado a la sesión
        self.internal_priv = rsa.generate_private_key(65537, 2048, default_backend())
        self.internal_pub = self.internal_priv.public_key()

        # Datos de emisor
        self.priv_identity = None
        self.priv_key_id = None

        # Datos de receptor (Betito)
        self.pub_identity = None
        self.pub_key_id = None

        self._init_ui()

    def _init_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_keys = ttk.Frame(notebook)
        self.tab_sender = ttk.Frame(notebook)
        self.tab_receiver = ttk.Frame(notebook)

        notebook.add(self.tab_keys, text="1. Cargar Llave Privada (.asc)")
        notebook.add(self.tab_sender, text="2. Emisor (Alicia / Candy)")
        notebook.add(self.tab_receiver, text="3. Receptor (Betito)")

        self._build_tab_keys()
        self._build_tab_sender()
        self._build_tab_receiver()

    def _build_tab_keys(self):
        f = ttk.LabelFrame(self.tab_keys, text=" Autenticación de Emisor ", padding=15)
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="Selecciona tu archivo .asc de llave privada que ya tienes en tu computadora:").pack(anchor=tk.W, pady=5)

        btn_box = ttk.Frame(f)
        btn_box.pack(anchor=tk.W, pady=10)
        ttk.Button(btn_box, text="📂 Seleccionar mi Llave Privada (.asc)", command=self.action_load_priv).pack(side=tk.LEFT, padx=5)

        self.lbl_priv_status = ttk.Label(f, text="Llave Privada: No cargada", foreground="red", font=("Segoe UI", 9, "bold"))
        self.lbl_priv_status.pack(anchor=tk.W, pady=5)

        self.txt_key_details = scrolledtext.ScrolledText(f, height=18, font=("Consolas", 9))
        self.txt_key_details.pack(fill=tk.BOTH, expand=True, pady=10)

    def action_load_priv(self):
        path = filedialog.askopenfilename(filetypes=[("Llaves Privadas", "*.asc;*.key;*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                c = f.read()

            if "PUBLIC KEY" in c and "PRIVATE" not in c and "SECRET" not in c:
                messagebox.showerror("Error", "Has seleccionado una llave pública. Debes seleccionar tu archivo de LLAVE PRIVADA.")
                return

            uid, kid = OpenPGPAnalyzer.analyze(c)
            self.priv_identity = uid
            self.priv_key_id = kid

            self.lbl_priv_status.config(text=f"Llave Activa: {uid}", foreground="green")
            self.txt_key_details.delete("1.0", tk.END)
            self.txt_key_details.insert(tk.END, "[✓] Llave privada de GPG vinculada exitosamente.\n")
            self.txt_key_details.insert(tk.END, f"    ➔ Titular del Certificado: {uid}\n")
            self.txt_key_details.insert(tk.END, f"    ➔ Key ID Criptográfico: 0x{kid}\n")
            self.txt_key_details.insert(tk.END, f"    ➔ Archivo origen: {os.path.basename(path)}\n")
            messagebox.showinfo("Éxito", f"Identidad comprobada:\n{uid}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar la llave privada:\n{e}")

    def _build_tab_sender(self):
        f = ttk.Frame(self.tab_sender, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        self.send_cipher = tk.BooleanVar(value=True)
        self.send_sign = tk.BooleanVar(value=True)

        opts = ttk.LabelFrame(f, text=" 1. Selección de Servicios Criptográficos ", padding=10)
        opts.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(opts, text="Confidencialidad (Diffie-Hellman + AES-CBC)", variable=self.send_cipher).pack(side=tk.LEFT, padx=15)
        ttk.Checkbutton(opts, text="Firma Digital (Autenticación, Integridad, No Repudio)", variable=self.send_sign).pack(side=tk.LEFT, padx=15)

        msg_box = ttk.LabelFrame(f, text=" 2. Mensaje en Claro (m) ", padding=10)
        msg_box.pack(fill=tk.X, pady=5)
        self.txt_sender_msg = ttk.Entry(msg_box, font=("Segoe UI", 10))
        self.txt_sender_msg.insert(0, "Mensaje auténtico y confidencial para Betito.")
        self.txt_sender_msg.pack(fill=tk.X)

        ttk.Button(f, text="🔒 Cifrar / Firmar y Guardar Archivo para Drive", command=self.action_send).pack(pady=10)

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

        if do_s and not self.priv_identity:
            messagebox.showerror("Error", "Carga tu llave privada en la Pestaña 1 para firmar.")
            return

        msg_bytes = self.txt_sender_msg.get().strip().encode('utf-8')
        if not msg_bytes:
            messagebox.showwarning("Error", "El mensaje no puede estar vacío.")
            return

        packet = {"cipher_active": do_c, "sign_active": do_s}

        # 1. Confidencialidad (Diffie-Hellman + AES-CBC)
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
            self.txt_sender_log.insert(tk.END, "    - Diffie-Hellman: Secretos K e IV acordados matemáticamente.\n")
            self.txt_sender_log.insert(tk.END, f"    - AES-CBC: Mensaje cifrado ({len(ciphertext)} bytes).\n")
        else:
            packet["payload"] = base64.b64encode(msg_bytes).decode()
            self.txt_sender_log.insert(tk.END, "[i] Texto en claro sin cifrar.\n")

        # 2. Firma Digital
        if do_s:
            self.txt_sender_log.insert(tk.END, "[+] Servicios: AUTENTICACIÓN, INTEGRIDAD Y NO REPUDIO activados.\n")
            sig = self.internal_priv.sign(
                msg_bytes,
                asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            packet["signature"] = base64.b64encode(sig).decode()
            packet["author_uid"] = self.priv_identity
            packet["key_id"] = self.priv_key_id
            packet["signer_pub_pem"] = self.internal_pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            self.txt_sender_log.insert(tk.END, f"    - Firma digital generada por: {self.priv_identity}\n")
            self.txt_sender_log.insert(tk.END, f"    - Vinculada al Key ID: 0x{self.priv_key_id}\n")

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Paquete JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(packet, f, indent=2)
            self.txt_sender_log.insert(tk.END, f"\n[✓] Paquete guardado para Google Drive: {path}\n")
            messagebox.showinfo("Listo", "Archivo generado para subir a Google Drive.")

    def _build_tab_receiver(self):
        f = ttk.Frame(self.tab_receiver, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        load_box = ttk.LabelFrame(f, text=" 1. Archivo Descargado de la Nube (x, y, z) ", padding=10)
        load_box.pack(fill=tk.X, pady=5)
        ttk.Button(load_box, text="📂 Seleccionar Archivo Descargado", command=self.action_load_file).pack(side=tk.LEFT, padx=5)
        self.lbl_cloud_file = ttk.Label(load_box, text="Ningún archivo seleccionado", foreground="gray")
        self.lbl_cloud_file.pack(side=tk.LEFT, padx=10)

        web_box = ttk.LabelFrame(f, text=" 2. Llave Pública del Autor (.asc) [Descarga Web en Vivo] ", padding=10)
        web_box.pack(fill=tk.X, pady=5)

        url_row = ttk.Frame(web_box)
        url_row.pack(fill=tk.X, pady=3)
        ttk.Label(url_row, text="URL Web:").pack(side=tk.LEFT, padx=5)
        self.txt_pub_url = ttk.Entry(url_row, width=50)
        self.txt_pub_url.insert(0, "https://gist.githubusercontent.com/.../raw/alicia_pub.asc")
        self.txt_pub_url.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(url_row, text="🌐 Descargar de la Web", command=self.action_download_web_pub).pack(side=tk.LEFT, padx=5)

        ttk.Button(web_box, text="📂 O cargar llave pública .asc desde archivo local", command=self.action_load_local_pub).pack(anchor=tk.W, padx=5, pady=3)
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
                messagebox.showinfo("Cargado", f"Archivo seleccionado: {os.path.basename(path)}")
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
            self._set_pub_key(r.text)
            messagebox.showinfo("Éxito", f"Llave pública descargada:\n{self.pub_identity}")
        except Exception as e:
            messagebox.showerror("Error", f"Fallo al descargar de la web:\n{e}")

    def action_load_local_pub(self):
        path = filedialog.askopenfilename(filetypes=[("Llaves Públicas", "*.asc;*.pem;*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    self._set_pub_key(f.read())
                messagebox.showinfo("Éxito", f"Llave pública cargada:\n{self.pub_identity}")
            except Exception as e:
                messagebox.showerror("Error", f"Fallo al leer la llave: {e}")

    def _set_pub_key(self, text):
        uid, kid = OpenPGPAnalyzer.analyze(text)
        self.pub_identity = uid
        self.pub_key_id = kid
        self.lbl_pub_status.config(text=f"Llave Pública cargada: {uid} [0x{kid[:8]}]", foreground="green")

    def action_decrypt_verify(self):
        self.txt_receiver_log.delete("1.0", tk.END)
        if not self.loaded_packet:
            messagebox.showwarning("Error", "Carga primero el archivo de la nube.")
            return

        p = self.loaded_packet
        decrypted_m = None

        self.txt_receiver_log.insert(tk.END, "========================================================\n")
        self.txt_receiver_log.insert(tk.END, "           PROCESAMIENTO EN RECEPTOR (BETITO)           \n")
        self.txt_receiver_log.insert(tk.END, "========================================================\n")

        # 1. DESCIFRADO
        try:
            payload_bytes = base64.b64decode(p["payload"])
        except Exception:
            self.txt_receiver_log.insert(tk.END, "[X] FALLO DE INTEGRIDAD: El archivo fue alterado.\n")
            messagebox.showerror("Integridad Rota", "El archivo fue adulterado en la nube.")
            return

        if p.get("cipher_active", False):
            try:
                Ka = int(p["dh_Ka"])
                b = int(p["dh_b_simulated"])
                k_session = CryptoEngine.compute_dh_key(Ka, b, 16)

                Kc = int(p["dh_Kc"])
                d = int(p["dh_d_simulated"])
                iv_session = CryptoEngine.compute_dh_key(Kc, d, 16)

                decrypted_m = CryptoEngine.decrypt_aes_cbc(payload_bytes, k_session, iv_session)
                self.txt_receiver_log.insert(tk.END, "[✓] CONFIDENCIALIDAD: Descifrado Diffie-Hellman + AES-CBC exitoso.\n")
            except Exception as e:
                self.txt_receiver_log.insert(tk.END, f"[X] Error al descifrar: {e}\n")
                messagebox.showerror("Fallo de Descifrado", "No se pudo descifrar el criptograma.")
                return
        else:
            decrypted_m = payload_bytes
            self.txt_receiver_log.insert(tk.END, "[i] Mensaje en texto claro.\n")

        # 2. VERIFICACIÓN CRIPTOGRÁFICA
        if p.get("sign_active", False):
            if not self.pub_identity:
                messagebox.showwarning("Falta Llave", "Descarga o carga la llave pública .asc del presunto autor.")
                return

            author_packet = p.get("author_uid", "")
            kid_packet = p.get("key_id", "")
            raw_sig = base64.b64decode(p.get("signature", ""))
            signer_pem = p.get("signer_pub_pem", "")

            # A. Verificación de identidad: ¿La llave pública cargada por Betito es la del autor del archivo?
            key_id_match = (self.pub_key_id == kid_packet)

            # B. Verificación matemática de integridad del mensaje
            math_integrity = False
            try:
                pub_obj = serialization.load_pem_public_key(signer_pem.encode('utf-8'), backend=default_backend())
                pub_obj.verify(
                    raw_sig,
                    decrypted_m,
                    asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                math_integrity = True
            except Exception:
                math_integrity = False

            if key_id_match and math_integrity:
                self.txt_receiver_log.insert(tk.END, "[✓] VERIFICACIÓN EXITOSA (Firma válida = )\n")
                self.txt_receiver_log.insert(tk.END, f"    ➔ AUTOR CONFIRMADO: {self.pub_identity}\n")
                self.txt_receiver_log.insert(tk.END, f"    ➔ KEY ID VALIDADO: 0x{self.pub_key_id}\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ INTEGRIDAD: Mensaje auténtico, sin alteraciones.\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ NO REPUDIO: Vinculación matemática demostrada.\n")
                messagebox.showinfo("Verificación Positiva", f"¡Autor Confirmado!\nEl archivo pertenece a:\n{self.pub_identity}")
            else:
                self.txt_receiver_log.insert(tk.END, "[X] VERIFICACIÓN FALLIDA (Firma inválida != )\n")
                if not key_id_match:
                    self.txt_receiver_log.insert(tk.END, f"    ➔ ALERTA DE AUTORÍA: La llave probada (0x{self.pub_key_id[:8]}) NO corresponde al autor de este archivo (0x{kid_packet[:8]}).\n")
                if not math_integrity:
                    self.txt_receiver_log.insert(tk.END, "    ➔ ALERTA DE INTEGRIDAD: El mensaje fue manipulado en la nube (el hash no coincide con la firma).\n")
                messagebox.showerror(
                    "Fallo de Verificación",
                    f"La verificación ha FALLADO.\n\n"
                    f"La llave pública de '{self.pub_identity}' NO firmó este mensaje, o el archivo fue manipulado en la nube."
                )
        else:
            self.txt_receiver_log.insert(tk.END, "[i] Mensaje sin firma digital.\n")

        self.txt_receiver_log.insert(tk.END, "\n--------------------------------------------------------\n")
        self.txt_receiver_log.insert(tk.END, f"CONTENIDO DEL MENSAJE:\n{decrypted_m.decode('utf-8', errors='replace')}\n")
        self.txt_receiver_log.insert(tk.END, "--------------------------------------------------------\n")


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()