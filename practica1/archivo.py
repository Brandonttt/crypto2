import os
import json
import base64
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# =====================================================================
# MOTOR CRIPTOGRÁFICO
# =====================================================================
class CryptoEngine:
    # Grupo 14 RFC 3526 (2048 bits)
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
        digest = hashlib.sha256(shared_bytes).digest()
        return digest[:length]

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

    @staticmethod
    def generate_rsa_keypair():
        priv = rsa.generate_private_key(65537, 2048, default_backend())
        return priv, priv.public_key()

    @staticmethod
    def sign(priv_key, data: bytes) -> bytes:
        return priv_key.sign(
            data,
            asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    @staticmethod
    def verify(pub_key, signature: bytes, data: bytes) -> bool:
        try:
            pub_key.verify(
                signature,
                data,
                asym_padding.PSS(asym_padding.MGF1(hashes.SHA256()), asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# =====================================================================
# APLICACIÓN GRÁFICA
# =====================================================================
class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Criptografía Híbrida - Sistema Integral")
        self.geometry("980x750")

        # Estado local de claves RSA
        self.rsa_priv = None
        self.rsa_pub = None

        self._init_ui()

    def _init_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_keys = ttk.Frame(notebook)
        self.tab_sender = ttk.Frame(notebook)
        self.tab_receiver = ttk.Frame(notebook)

        notebook.add(self.tab_keys, text="Gestión de Identidad y Claves RSA")
        notebook.add(self.tab_sender, text="Emisor: Cifrado y Firma (Alicia / Candy)")
        notebook.add(self.tab_receiver, text="Receptor: Descifrado y Verificación (Betito)")

        self._build_tab_keys()
        self._build_tab_sender()
        self._build_tab_receiver()

    # -------------------------------------------------------------
    # Pestaña 1: Claves RSA
    # -------------------------------------------------------------
    def _build_tab_keys(self):
        f = ttk.LabelFrame(self.tab_keys, text=" Generador de Identidad Digital (RSA 2048) ", padding=15)
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="Genera tu par de claves para identificarte como Alicia, Candy o Betito:").pack(anchor=tk.W, pady=5)
        
        btn_box = ttk.Frame(f)
        btn_box.pack(anchor=tk.W, pady=10)
        ttk.Button(btn_box, text="Generar Nuevo Par RSA", command=self.action_gen_rsa).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_box, text="Exportar Llave Pública (.pem)", command=self.action_save_pub).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_box, text="Exportar Llave Privada (.pem)", command=self.action_save_priv).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_box, text="Cargar Llave Privada (.pem)", command=self.action_load_priv).pack(side=tk.LEFT, padx=5)

        self.txt_keys_info = scrolledtext.ScrolledText(f, height=18, font=("Consolas", 9))
        self.txt_keys_info.pack(fill=tk.BOTH, expand=True, pady=10)

    def action_gen_rsa(self):
        self.rsa_priv, self.rsa_pub = CryptoEngine.generate_rsa_keypair()
        pub_pem = self.rsa_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.txt_keys_info.delete("1.0", tk.END)
        self.txt_keys_info.insert(tk.END, "[✓] Par de claves RSA 2048 generado correctamente.\n\n")
        self.txt_keys_info.insert(tk.END, "--- CLAVE PÚBLICA (Para subir a la web/drive) ---\n" + pub_pem)
        messagebox.showinfo("Éxito", "Claves RSA listas en memoria. Exporta tu clave pública para compartirla.")

    def action_save_pub(self):
        if not self.rsa_pub:
            messagebox.showwarning("Aviso", "Primero genera un par de claves.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
        if path:
            pem = self.rsa_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            with open(path, "wb") as f: f.write(pem)
            messagebox.showinfo("Guardado", f"Clave pública exportada en:\n{path}")

    def action_save_priv(self):
        if not self.rsa_priv:
            messagebox.showwarning("Aviso", "Primero genera un par de claves.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
        if path:
            pem = self.rsa_priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            with open(path, "wb") as f: f.write(pem)
            messagebox.showinfo("Guardado", f"Clave privada exportada en:\n{path}")

    def action_load_priv(self):
        path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if path:
            with open(path, "rb") as f:
                self.rsa_priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                self.rsa_pub = self.rsa_priv.public_key()
            messagebox.showinfo("Cargado", "Clave privada cargada con éxito en memoria.")

    # -------------------------------------------------------------
    # Pestaña 2: Emisor (Alicia / Candy)
    # -------------------------------------------------------------
    def _build_tab_sender(self):
        f = ttk.Frame(self.tab_sender, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        self.send_cipher = tk.BooleanVar(value=True)
        self.send_sign = tk.BooleanVar(value=True)

        opts = ttk.LabelFrame(f, text=" 1. Selección de Servicios ", padding=10)
        opts.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(opts, text="Cifrado (Confidencialidad vía DH + AES-CBC)", variable=self.send_cipher).pack(side=tk.LEFT, padx=15)
        ttk.Checkbutton(opts, text="Firma Digital (Autenticación, Integridad, No Repudio vía RSA)", variable=self.send_sign).pack(side=tk.LEFT, padx=15)

        msg_box = ttk.LabelFrame(f, text=" 2. Mensaje en Claro (m) ", padding=10)
        msg_box.pack(fill=tk.X, pady=5)
        self.txt_sender_msg = ttk.Entry(msg_box, font=("Segoe UI", 10))
        self.txt_sender_msg.insert(0, "Hola Betito, este es un mensaje auténtico y confidencial.")
        self.txt_sender_msg.pack(fill=tk.X)

        btn_run = ttk.Button(f, text="🔒 Ejecutar y Guardar Archivo Criptográfico para la Nube", command=self.action_process_and_save)
        btn_run.pack(pady=10)

        log_box = ttk.LabelFrame(f, text=" Bitácora del Proceso (Servicios y Operaciones) ", padding=10)
        log_box.pack(fill=tk.BOTH, expand=True, pady=5)
        self.txt_sender_log = scrolledtext.ScrolledText(log_box, height=12, font=("Consolas", 9))
        self.txt_sender_log.pack(fill=tk.BOTH, expand=True)

    def action_process_and_save(self):
        self.txt_sender_log.delete("1.0", tk.END)
        do_c = self.send_cipher.get()
        do_s = self.send_sign.get()

        if not do_c and not do_s:
            messagebox.showwarning("Error", "Seleccione al menos un servicio.")
            return

        if do_s and not self.rsa_priv:
            messagebox.showerror("Error", "Para firmar debe generar o cargar su llave privada en la pestaña 'Gestión de Claves'.")
            return

        msg_bytes = self.txt_sender_msg.get().strip().encode('utf-8')
        if not msg_bytes:
            messagebox.showwarning("Error", "El mensaje no puede estar vacío.")
            return

        self.txt_sender_log.insert(tk.END, "[*] Iniciando procesamiento del mensaje...\n")
        
        packet = {"cipher_active": do_c, "sign_active": do_s}

        # Diffie-Hellman simulando acuerdo con Betito
        if do_c:
            self.txt_sender_log.insert(tk.END, "[+] Servicio: CONFIDENCIALIDAD activado.\n")
            # Ronda K
            a, Ka = CryptoEngine.generate_dh_pair()
            b, Kb = CryptoEngine.generate_dh_pair()
            k_session = CryptoEngine.compute_dh_key(Kb, a, 16)

            # Ronda IV
            c, Kc = CryptoEngine.generate_dh_pair()
            d, Kd = CryptoEngine.generate_dh_pair()
            iv_session = CryptoEngine.compute_dh_key(Kd, c, 16)

            ciphertext = CryptoEngine.encrypt_aes_cbc(msg_bytes, k_session, iv_session)
            
            # Guardamos datos de sesión para que el receptor pueda derivar la misma clave
            packet["dh_Ka"] = str(Ka)
            packet["dh_b_simulated"] = str(b)  # Permite al receptor calcular K = Ka^b mod n
            packet["dh_Kc"] = str(Kc)
            packet["dh_d_simulated"] = str(d)  # Permite al receptor calcular IV = Kc^d mod n
            packet["payload"] = base64.b64encode(ciphertext).decode()

            self.txt_sender_log.insert(tk.END, f"    - Ronda DH (K): Ka y Kb intercambiados. K derivada.\n")
            self.txt_sender_log.insert(tk.END, f"    - Ronda DH (IV): Kc y Kd intercambiados. IV derivado.\n")
            self.txt_sender_log.insert(tk.END, f"    - Cifrado AES-CBC completado ({len(ciphertext)} bytes).\n")
        else:
            packet["payload"] = base64.b64encode(msg_bytes).decode()
            self.txt_sender_log.insert(tk.END, "[i] Confidencialidad NO seleccionada: el texto viaja en claro.\n")

        # Firma RSA
        if do_s:
            self.txt_sender_log.insert(tk.END, "[+] Servicios: AUTENTICACIÓN, INTEGRIDAD Y NO REPUDIO activados.\n")
            sig = CryptoEngine.sign(self.rsa_priv, msg_bytes)
            packet["signature"] = base64.b64encode(sig).decode()
            self.txt_sender_log.insert(tk.END, f"    - Hash SHA-256 generado y firmado con RSA privada.\n")
            self.txt_sender_log.insert(tk.END, f"    - Firma digital adjunta: {sig.hex()[:30]}...\n")

        # Guardar en archivo
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Crypto Package", "*.json;*.bin;*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(packet, f, indent=2)
            self.txt_sender_log.insert(tk.END, f"\n[✓] Paquete guardado con éxito en: {path}\n")
            self.txt_sender_log.insert(tk.END, "[✓] LISTO PARA SUBIR A LA NUBE (Google Drive).\n")
            messagebox.showinfo("Completado", "Archivo generado. Ya puedes subirlo a Drive.")

    # -------------------------------------------------------------
    # Pestaña 3: Receptor (Betito)
    # -------------------------------------------------------------
    def _build_tab_receiver(self):
        f = ttk.Frame(self.tab_receiver, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        load_box = ttk.LabelFrame(f, text=" 1. Cargar Archivo de la Nube (x, y, z) ", padding=10)
        load_box.pack(fill=tk.X, pady=5)
        
        btn_row1 = ttk.Frame(load_box)
        btn_row1.pack(fill=tk.X)
        ttk.Button(btn_row1, text="Seleccionar Archivo Local Descargado de Drive", command=self.action_load_cloud_file).pack(side=tk.LEFT, padx=5)
        self.lbl_cloud_file = ttk.Label(btn_row1, text="Ningún archivo seleccionado", foreground="gray")
        self.lbl_cloud_file.pack(side=tk.LEFT, padx=10)

        web_box = ttk.LabelFrame(f, text=" 2. Obtención de Llave Pública del Autor (Descarga Web Requerida) ", padding=10)
        web_box.pack(fill=tk.X, pady=5)

        url_row = ttk.Frame(web_box)
        url_row.pack(fill=tk.X, pady=3)
        ttk.Label(url_row, text="URL Llave Pública:").pack(side=tk.LEFT, padx=5)
        self.txt_pub_url = ttk.Entry(url_row, width=50)
        self.txt_pub_url.insert(0, "https://raw.githubusercontent.com/.../alicia_public.pem")
        self.txt_pub_url.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(url_row, text="🌐 Descargar de la Web", command=self.action_download_pub_web).pack(side=tk.LEFT, padx=5)

        ttk.Button(web_box, text="O cargar llave pública desde archivo local", command=self.action_load_pub_file).pack(anchor=tk.W, padx=5, pady=3)
        self.lbl_pub_status = ttk.Label(web_box, text="Llave pública: No cargada", foreground="red")
        self.lbl_pub_status.pack(anchor=tk.W, padx=5)

        btn_verify = ttk.Button(f, text="🔓 Descifrar y Verificar Identidad / Integridad", command=self.action_decrypt_and_verify)
        btn_verify.pack(pady=10)

        res_box = ttk.LabelFrame(f, text=" Resultados de Verificación y Contenido ", padding=10)
        res_box.pack(fill=tk.BOTH, expand=True, pady=5)
        self.txt_receiver_log = scrolledtext.ScrolledText(res_box, height=12, font=("Consolas", 9))
        self.txt_receiver_log.pack(fill=tk.BOTH, expand=True)

        self.loaded_packet = None
        self.received_pub_key = None

    def action_load_cloud_file(self):
        path = filedialog.askopenfilename(filetypes=[("Archivos de paquete", "*.json;*.bin;*.txt;*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.loaded_packet = json.load(f)
                self.lbl_cloud_file.config(text=os.path.basename(path), foreground="black")
                messagebox.showinfo("Cargado", f"Archivo cargado: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el archivo: {e}")

    def action_download_pub_web(self):
        url = self.txt_pub_url.get().strip()
        if not url:
            messagebox.showwarning("Error", "Proporcione la URL de la clave pública.")
            return
        try:
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            self.received_pub_key = serialization.load_pem_public_key(r.content, backend=default_backend())
            self.lbl_pub_status.config(text="Llave pública descargada exitosamente vía Web", foreground="green")
            messagebox.showinfo("Éxito", "Clave pública descargada y parseada desde la Web.")
        except Exception as e:
            messagebox.showerror("Error de Red/Formato", f"Fallo al descargar la clave:\n{e}")

    def action_load_pub_file(self):
        path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if path:
            with open(path, "rb") as f:
                self.received_pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            self.lbl_pub_status.config(text=f"Llave local cargada: {os.path.basename(path)}", foreground="green")

    def action_decrypt_and_verify(self):
        self.txt_receiver_log.delete("1.0", tk.END)
        if not self.loaded_packet:
            messagebox.showwarning("Error", "Cargue primero el archivo de la nube.")
            return

        self.txt_receiver_log.insert(tk.END, "========================================================\n")
        self.txt_receiver_log.insert(tk.END, "             INSPECCIÓN Y RECEPCIÓN DE BETITO           \n")
        self.txt_receiver_log.insert(tk.END, "========================================================\n")

        p = self.loaded_packet
        payload_bytes = base64.b64decode(p["payload"])
        decrypted_m = None

        # 1. DESCIFRADO
        if p.get("cipher_active", False):
            self.txt_receiver_log.insert(tk.END, "[*] Procesando Confidencialidad (Diffie-Hellman + AES-CBC)...\n")
            try:
                Ka = int(p["dh_Ka"])
                b = int(p["dh_b_simulated"])
                k_session = CryptoEngine.compute_dh_key(Ka, b, 16)

                Kc = int(p["dh_Kc"])
                d = int(p["dh_d_simulated"])
                iv_session = CryptoEngine.compute_dh_key(Kc, d, 16)

                decrypted_m = CryptoEngine.decrypt_aes_cbc(payload_bytes, k_session, iv_session)
                self.txt_receiver_log.insert(tk.END, f"[✓] Confidencialidad garantizada: AES-CBC descifrado con éxito.\n")
            except Exception as e:
                self.txt_receiver_log.insert(tk.END, f"[X] Error crítico al descifrar: {e}\n")
                messagebox.showerror("Fallo de Descifrado", "No se pudo descifrar el criptograma.")
                return
        else:
            decrypted_m = payload_bytes
            self.txt_receiver_log.insert(tk.END, "[i] El archivo no incluye capa de confidencialidad.\n")

        # 2. VERIFICACIÓN DE IDENTIDAD E INTEGRIDAD
        if p.get("sign_active", False):
            self.txt_receiver_log.insert(tk.END, "\n[*] Procesando Verificación de Firma RSA...\n")
            if not self.received_pub_key:
                self.txt_receiver_log.insert(tk.END, "[!] Advertencia: Debe descargar la llave pública del supuesto autor.\n")
                messagebox.showwarning("Falta Llave", "Descargue o cargue la llave pública para validar el autor.")
                return

            sig = base64.b64decode(p["signature"])
            is_valid = CryptoEngine.verify(self.received_pub_key, sig, decrypted_m)

            if is_valid:
                self.txt_receiver_log.insert(tk.END, "[✓] VERIFICACIÓN EXITOSA (Hash coincide = )\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ AUTENTICACIÓN: El autor posee la clave privada correspondiente.\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ INTEGRIDAD: El mensaje no ha sufrido ninguna modificación.\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ NO REPUDIO: El autor no puede negar haber emitido este mensaje.\n")
                messagebox.showinfo("Verificación Positiva", "Firma válida: Identidad e Integridad confirmadas.")
            else:
                self.txt_receiver_log.insert(tk.END, "[X] VERIFICACIÓN FALLIDA (Hash NO coincide != )\n")
                self.txt_receiver_log.insert(tk.END, "    ➔ ALERTA DE INTEGRIDAD: El archivo fue alterado o la llave pública no corresponde al autor.\n")
                messagebox.showerror("Fallo de Integridad / Firma", "La firma NO coincide. El archivo fue manipulado o la llave pública es incorrecta.")
        else:
            self.txt_receiver_log.insert(tk.END, "[i] El archivo no incluye firma digital.\n")

        self.txt_receiver_log.insert(tk.END, "\n--------------------------------------------------------\n")
        self.txt_receiver_log.insert(tk.END, f"CONTENIDO DEL MENSAJE:\n{decrypted_m.decode('utf-8', errors='replace')}\n")
        self.txt_receiver_log.insert(tk.END, "--------------------------------------------------------\n")


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()