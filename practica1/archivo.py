"""
Practica: Criptografia Hibrida  -  ESCOM / IPN
Dra. Nidia A. Cortez Duarte

Esquema implementado (diagrama inferior del enunciado):

    Emisor (Alicia / Candy)                         Receptor (Betito)
    ------------------------                        -----------------
    m --AES-CBC(K, IV)--> C                         C --AES-CBC(K, IV)--> m
    K  = SHA-256(Kb^a mod p)[:16]   <-- DH #1 -->    K  = SHA-256(Ka^b mod p)[:16]
    IV = SHA-256(Kd^c mod p)[:16]   <-- DH #2 -->    IV = SHA-256(Kc^d mod p)[:16]
    m --SHA-256--> h --RSA(privA)--> firma           firma --RSA(pubA)--> h' ?= SHA-256(m)

Servicios ofrecidos:
  * Confidencialidad ......... AES-128-CBC con K e IV acordados por Diffie-Hellman.
  * Integridad ............... SHA-256 del mensaje, protegido por la firma.
  * Autenticacion ............ la firma solo verifica con la llave publica que el
                               autor publico en su pagina web.
  * No repudio ............... solo el poseedor de la llave privada RSA pudo
                               producir esa firma.

Modulos: pgp.py (lector OpenPGP RFC 4880), motor.py (DH + AES + SHA-256),
protocolo.py (formato de los archivos). Las referencias bibliograficas de cada
funcion reutilizada estan al inicio de cada modulo y en la pestania "Referencias".

Ejecucion:  python archivo.py      (requiere: pip install -r requirements.txt)
"""

import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from typing import Dict, List, Optional

import motor
import pgp
import protocolo
from pgp import PGPKey

COLOR_OK = "#0a7d34"
COLOR_ERR = "#b3261e"
COLOR_INFO = "#1a4f8a"


class Bitacora:
    """Envoltorio del area de texto para escribir con estilos."""

    def __init__(self, padre, alto=14):
        self.widget = scrolledtext.ScrolledText(
            padre, height=alto, font=("Consolas", 9), wrap=tk.WORD
        )
        self.widget.pack(fill=tk.BOTH, expand=True)
        self.widget.tag_config("ok", foreground=COLOR_OK)
        self.widget.tag_config("err", foreground=COLOR_ERR)
        self.widget.tag_config("info", foreground=COLOR_INFO)
        self.widget.tag_config("titulo", font=("Consolas", 10, "bold"))

    def limpiar(self):
        self.widget.delete("1.0", tk.END)

    def escribir(self, texto, tag=None):
        self.widget.insert(tk.END, texto + "\n", tag or ())
        self.widget.see(tk.END)

    def ok(self, t):
        self.escribir("[OK] " + t, "ok")

    def error(self, t):
        self.escribir("[!!] " + t, "err")

    def info(self, t):
        self.escribir("[  ] " + t)

    def paso(self, t):
        self.escribir("     " + t, "info")

    def titulo(self, t):
        self.escribir("")
        self.escribir("=" * 72)
        self.escribir(t, "titulo")
        self.escribir("=" * 72)


def descargar_texto(url: str, timeout: int = 10) -> str:
    """Descarga un recurso de texto de la web (llave publica o parametros DH)."""
    try:
        import requests  # dependencia declarada en requirements.txt
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Falta la libreria 'requests'. Instalala con: pip install requests"
        ) from exc
    respuesta = requests.get(url, timeout=timeout)
    respuesta.raise_for_status()
    return respuesta.text


class AplicacionHibrida(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Criptografia Hibrida - Diffie-Hellman + AES-CBC + Firma RSA (OpenPGP)")
        self.geometry("1060x820")
        self.minsize(900, 700)

        # --- Estado compartido ---
        self.mi_llave: Optional[PGPKey] = None          # llave propia (con privada)
        self.dest_llave: Optional[PGPKey] = None        # llave publica del destinatario
        self.dest_dh: Optional[Dict] = None             # parametros DH verificados
        self.llavero: List[PGPKey] = []                 # posibles autores (receptor)
        self.paquetes: List[Dict] = []                  # archivos x, y, z cargados

        self._crear_menu()
        self._crear_pestanias()

    # ------------------------------------------------------------------
    # Menu principal (requisito del enunciado)
    # ------------------------------------------------------------------
    def _crear_menu(self):
        barra = tk.Menu(self)

        m_proceso = tk.Menu(barra, tearoff=0)
        m_proceso.add_command(
            label="Cifrado + Firma  (dos de dos servicios)",
            command=lambda: self._preparar_envio(True, True),
        )
        m_proceso.add_command(
            label="Solo Cifrado  (confidencialidad)",
            command=lambda: self._preparar_envio(True, False),
        )
        m_proceso.add_command(
            label="Solo Firma  (autenticacion, integridad, no repudio)",
            command=lambda: self._preparar_envio(False, True),
        )
        m_proceso.add_separator()
        m_proceso.add_command(
            label="Descifrado / Verificacion", command=lambda: self.cuaderno.select(2)
        )
        m_proceso.add_separator()
        m_proceso.add_command(label="Salir", command=self.destroy)
        barra.add_cascade(label="Proceso", menu=m_proceso)

        m_llaves = tk.Menu(barra, tearoff=0)
        m_llaves.add_command(label="Cargar mi llave privada .asc", command=self.cargar_mi_llave)
        m_llaves.add_command(
            label="Exportar mis parametros DH publicos", command=self.exportar_dhpub
        )
        barra.add_cascade(label="Llaves", menu=m_llaves)

        m_ayuda = tk.Menu(barra, tearoff=0)
        m_ayuda.add_command(label="Referencias y algoritmos", command=lambda: self.cuaderno.select(3))
        barra.add_cascade(label="Ayuda", menu=m_ayuda)

        self.config(menu=barra)

    def _preparar_envio(self, cifrar: bool, firmar: bool):
        self.var_cifrar.set(cifrar)
        self.var_firmar.set(firmar)
        self.cuaderno.select(1)

    def _crear_pestanias(self):
        self.cuaderno = ttk.Notebook(self)
        self.cuaderno.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.tab_id = ttk.Frame(self.cuaderno)
        self.tab_emisor = ttk.Frame(self.cuaderno)
        self.tab_receptor = ttk.Frame(self.cuaderno)
        self.tab_refs = ttk.Frame(self.cuaderno)

        self.cuaderno.add(self.tab_id, text=" 1. Mi identidad (.asc) ")
        self.cuaderno.add(self.tab_emisor, text=" 2. Emisor: cifrar y firmar ")
        self.cuaderno.add(self.tab_receptor, text=" 3. Receptor: descifrar y verificar ")
        self.cuaderno.add(self.tab_refs, text=" 4. Referencias ")

        self._construir_identidad()
        self._construir_emisor()
        self._construir_receptor()
        self._construir_referencias()

    # ==================================================================
    # PESTANIA 1 - Identidad
    # ==================================================================
    def _construir_identidad(self):
        marco = ttk.Frame(self.tab_id, padding=14)
        marco.pack(fill=tk.BOTH, expand=True)

        caja = ttk.LabelFrame(marco, text=" Mi llave privada OpenPGP ", padding=12)
        caja.pack(fill=tk.X)
        ttk.Label(
            caja,
            text=(
                "Carga tu llave PRIVADA .asc (gpg --export-secret-keys --armor TU_ID > privada.asc).\n"
                "Se usa para firmar y para derivar tu par Diffie-Hellman estatico. Nunca sale de tu equipo."
            ),
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 8))

        fila = ttk.Frame(caja)
        fila.pack(anchor=tk.W)
        ttk.Button(fila, text="Seleccionar mi llave privada .asc", command=self.cargar_mi_llave).pack(
            side=tk.LEFT
        )
        ttk.Button(
            fila, text="Exportar mis parametros DH publicos", command=self.exportar_dhpub
        ).pack(side=tk.LEFT, padx=8)

        self.lbl_identidad = ttk.Label(
            caja, text="Sin llave cargada", foreground=COLOR_ERR, font=("Segoe UI", 9, "bold")
        )
        self.lbl_identidad.pack(anchor=tk.W, pady=8)

        detalle = ttk.LabelFrame(marco, text=" Detalle del certificado ", padding=10)
        detalle.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_id = Bitacora(detalle, alto=20)
        self.log_id.info("Aun no se ha cargado ninguna llave.")
        self.log_id.info(
            "Esta aplicacion interpreta los paquetes OpenPGP del archivo .asc (RFC 4880):"
        )
        self.log_id.paso("extrae el modulo n y el exponente e del paquete de llave publica;")
        self.log_id.paso("descifra el material privado protegido con S2K para obtener d, p y q;")
        self.log_id.paso("y reconstruye la llave RSA para firmar de verdad con ella.")

    def cargar_mi_llave(self):
        ruta = filedialog.askopenfilename(
            title="Selecciona tu llave privada OpenPGP",
            filetypes=[("Llaves OpenPGP", "*.asc"), ("Todos", "*.*")],
        )
        if not ruta:
            return
        try:
            texto = pgp.leer_texto(ruta)
        except OSError as exc:
            messagebox.showerror("Error", f"No se pudo leer el archivo:\n{exc}")
            return

        if not pgp.looks_like_secret_key(texto):
            messagebox.showerror(
                "Archivo incorrecto",
                "Ese archivo no contiene una llave PRIVADA de OpenPGP.\n\n"
                "Exportala con:\n  gpg --export-secret-keys --armor TU_ID > privada.asc",
            )
            return

        frase = ""
        if pgp.needs_passphrase(texto):
            frase = simpledialog.askstring(
                "Frase de paso",
                "La llave privada esta protegida.\nEscribe su frase de paso:",
                show="*",
                parent=self,
            )
            if frase is None:
                return

        try:
            llave = pgp.load_secret_key(texto, frase)
        except pgp.PGPError as exc:
            messagebox.showerror("No se pudo abrir la llave", str(exc))
            return

        self.mi_llave = llave
        self.lbl_identidad.config(text=f"Identidad activa: {llave.uid}", foreground=COLOR_OK)

        _, kb = motor.derivar_par_estatico(llave.private_key, motor.ETIQUETA_K)
        _, kd = motor.derivar_par_estatico(llave.private_key, motor.ETIQUETA_IV)

        self.log_id.limpiar()
        self.log_id.titulo("LLAVE PRIVADA OPENPGP CARGADA Y DESCIFRADA")
        self.log_id.ok(f"Usuario (User ID)  : {llave.uid}")
        self.log_id.info(f"Key ID             : {llave.key_id}")
        self.log_id.info(f"Huella digital     : {llave.pretty_fingerprint()}")
        self.log_id.info(f"Algoritmo          : {llave.algo_name}, {llave.bits} bits")
        self.log_id.info(f"Archivo            : {os.path.basename(ruta)}")
        self.log_id.escribir("")
        self.log_id.escribir("Par Diffie-Hellman estatico derivado de esta llave:", "titulo")
        self.log_id.paso(f"Grupo : {motor.GRUPO_DH}")
        self.log_id.paso(f"Kb (para la llave K de AES) : {format(kb, 'x')[:64]}...")
        self.log_id.paso(f"Kd (para el IV de AES)      : {format(kd, 'x')[:64]}...")
        self.log_id.escribir("")
        self.log_id.info(
            "Publica tus parametros DH (boton de arriba) en tu pagina web junto a tu .asc "
            "para que Alicia y Candy puedan cifrarte."
        )
        self.lbl_receptor_id.config(text=f"Receptor: {llave.uid}", foreground=COLOR_OK)
        self.lbl_emisor_id.config(text=f"Firmara: {llave.uid}", foreground=COLOR_OK)

    def exportar_dhpub(self):
        if not self.mi_llave or not self.mi_llave.private_key:
            messagebox.showwarning("Falta la llave", "Primero carga tu llave privada .asc.")
            return
        try:
            bloque = protocolo.construir_dhpub(self.mi_llave)
        except protocolo.ErrorProtocolo as exc:
            messagebox.showerror("Error", str(exc))
            return

        sugerido = self.mi_llave.uid.split("<")[0].strip().split(" ")[0].lower() or "mis"
        ruta = filedialog.asksaveasfilename(
            title="Guardar parametros DH publicos para publicar en la web",
            defaultextension=".json",
            initialfile=f"{sugerido}_dh.json",
            filetypes=[("Parametros DH publicos", "*.json")],
        )
        if not ruta:
            return
        protocolo.guardar_json(ruta, bloque)
        self.log_id.escribir("")
        self.log_id.ok(f"Parametros DH publicos guardados en: {ruta}")
        self.log_id.paso("Van firmados con tu llave RSA: nadie puede sustituirlos sin que se note.")
        messagebox.showinfo(
            "Listo",
            "Sube este archivo a tu pagina web, junto a tu llave publica .asc.\n\n"
            "Quien te escriba descargara ambos: el .asc para verificar la firma de\n"
            "los parametros, y los parametros para hacer el Diffie-Hellman.",
        )

    # ==================================================================
    # PESTANIA 2 - Emisor
    # ==================================================================
    def _construir_emisor(self):
        marco = ttk.Frame(self.tab_emisor, padding=12)
        marco.pack(fill=tk.BOTH, expand=True)

        self.var_cifrar = tk.BooleanVar(value=True)
        self.var_firmar = tk.BooleanVar(value=True)

        serv = ttk.LabelFrame(marco, text=" 1. Servicios criptograficos a ofrecer ", padding=10)
        serv.pack(fill=tk.X)
        ttk.Checkbutton(
            serv,
            text="Confidencialidad  (Diffie-Hellman + AES-128-CBC)",
            variable=self.var_cifrar,
        ).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(
            serv,
            text="Firma digital  (autenticacion + integridad + no repudio)",
            variable=self.var_firmar,
        ).pack(side=tk.LEFT, padx=10)
        self.lbl_emisor_id = ttk.Label(serv, text="Sin llave privada", foreground=COLOR_ERR)
        self.lbl_emisor_id.pack(side=tk.RIGHT, padx=10)

        dest = ttk.LabelFrame(
            marco,
            text=" 2. Destinatario: descargar su llave publica y sus parametros DH de su pagina web ",
            padding=10,
        )
        dest.pack(fill=tk.X, pady=8)

        f1 = ttk.Frame(dest)
        f1.pack(fill=tk.X, pady=2)
        ttk.Label(f1, text="URL llave publica .asc :", width=24).pack(side=tk.LEFT)
        self.url_dest_asc = ttk.Entry(f1)
        self.url_dest_asc.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(f1, text="Descargar", command=self.descargar_dest_asc).pack(side=tk.LEFT)
        ttk.Button(f1, text="Archivo local", command=self.local_dest_asc).pack(side=tk.LEFT, padx=4)

        f2 = ttk.Frame(dest)
        f2.pack(fill=tk.X, pady=2)
        ttk.Label(f2, text="URL parametros DH     :", width=24).pack(side=tk.LEFT)
        self.url_dest_dh = ttk.Entry(f2)
        self.url_dest_dh.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(f2, text="Descargar", command=self.descargar_dest_dh).pack(side=tk.LEFT)
        ttk.Button(f2, text="Archivo local", command=self.local_dest_dh).pack(side=tk.LEFT, padx=4)

        self.lbl_dest = ttk.Label(dest, text="Destinatario: no configurado", foreground=COLOR_ERR)
        self.lbl_dest.pack(anchor=tk.W, pady=(6, 0))

        msg = ttk.LabelFrame(marco, text=" 3. Mensaje en claro (m) ", padding=10)
        msg.pack(fill=tk.X, pady=4)
        self.txt_mensaje = tk.Text(msg, height=5, font=("Segoe UI", 10), wrap=tk.WORD)
        self.txt_mensaje.insert("1.0", "Hola Betito, este mensaje es confidencial y viene firmado.")
        self.txt_mensaje.pack(fill=tk.X)
        ttk.Button(msg, text="Cargar mensaje desde archivo .txt", command=self.cargar_mensaje).pack(
            anchor=tk.W, pady=(6, 0)
        )

        ttk.Button(
            marco,
            text="Generar paquete criptografico y guardarlo para el Drive",
            command=self.generar_paquete,
        ).pack(pady=10)

        caja_log = ttk.LabelFrame(marco, text=" Bitacora del emisor ", padding=8)
        caja_log.pack(fill=tk.BOTH, expand=True)
        self.log_emisor = Bitacora(caja_log, alto=12)
        self.log_emisor.info("Selecciona los servicios, configura al destinatario y genera el paquete.")

    def cargar_mensaje(self):
        ruta = filedialog.askopenfilename(filetypes=[("Texto", "*.txt"), ("Todos", "*.*")])
        if not ruta:
            return
        self.txt_mensaje.delete("1.0", tk.END)
        self.txt_mensaje.insert("1.0", pgp.leer_texto(ruta))

    def _fijar_dest_asc(self, texto: str, origen: str):
        llave = pgp.load_public_key(texto)
        self.dest_llave = llave
        self.dest_dh = None  # obliga a volver a verificar los parametros
        self.lbl_dest.config(
            text=f"Llave publica de {llave.uid} ({llave.short_id()}) - falta verificar sus parametros DH",
            foreground=COLOR_INFO,
        )
        self.log_emisor.ok(f"Llave publica del destinatario obtenida de {origen}")
        self.log_emisor.paso(f"UID   : {llave.uid}")
        self.log_emisor.paso(f"Huella: {llave.pretty_fingerprint()}")
        self.log_emisor.paso("Compara esta huella con la que el destinatario publico. ")

    def descargar_dest_asc(self):
        url = self.url_dest_asc.get().strip()
        if not url:
            messagebox.showwarning("Falta la URL", "Escribe la URL de la llave publica .asc.")
            return
        try:
            self._fijar_dest_asc(descargar_texto(url), f"la web ({url})")
        except Exception as exc:  # noqa: BLE001
            self.log_emisor.error(f"No se pudo descargar la llave publica: {exc}")
            messagebox.showerror("Error", f"No se pudo descargar la llave publica:\n{exc}")

    def local_dest_asc(self):
        ruta = filedialog.askopenfilename(filetypes=[("Llaves OpenPGP", "*.asc"), ("Todos", "*.*")])
        if not ruta:
            return
        try:
            self._fijar_dest_asc(pgp.leer_texto(ruta), os.path.basename(ruta))
        except (pgp.PGPError, OSError) as exc:
            self.log_emisor.error(f"Llave publica invalida: {exc}")
            messagebox.showerror("Error", str(exc))

    def _fijar_dest_dh(self, texto: str, origen: str):
        if not self.dest_llave:
            messagebox.showwarning(
                "Falta la llave publica",
                "Primero descarga la llave publica .asc del destinatario: se necesita "
                "para verificar la firma de sus parametros Diffie-Hellman.",
            )
            return
        datos = json.loads(texto)
        verificados = protocolo.verificar_dhpub(datos, self.dest_llave)
        self.dest_dh = verificados
        self.lbl_dest.config(
            text=f"Destinatario listo: {self.dest_llave.uid} ({self.dest_llave.short_id()})",
            foreground=COLOR_OK,
        )
        self.log_emisor.ok(f"Parametros Diffie-Hellman obtenidos de {origen} y VERIFICADOS")
        self.log_emisor.paso(
            "La firma RSA de los parametros corresponde a la llave publica del destinatario:"
        )
        self.log_emisor.paso("Diffie-Hellman autenticado, sin riesgo de hombre en medio.")
        self.log_emisor.paso(f"Kb = {format(verificados['Kb'], 'x')[:56]}...")
        self.log_emisor.paso(f"Kd = {format(verificados['Kd'], 'x')[:56]}...")

    def descargar_dest_dh(self):
        url = self.url_dest_dh.get().strip()
        if not url:
            messagebox.showwarning("Falta la URL", "Escribe la URL de los parametros DH.")
            return
        try:
            self._fijar_dest_dh(descargar_texto(url), f"la web ({url})")
        except protocolo.ErrorProtocolo as exc:
            self.log_emisor.error(str(exc))
            messagebox.showerror("Parametros DH rechazados", str(exc))
        except Exception as exc:  # noqa: BLE001
            self.log_emisor.error(f"No se pudieron descargar los parametros DH: {exc}")
            messagebox.showerror("Error", f"No se pudieron descargar los parametros DH:\n{exc}")

    def local_dest_dh(self):
        ruta = filedialog.askopenfilename(filetypes=[("Parametros DH", "*.json"), ("Todos", "*.*")])
        if not ruta:
            return
        try:
            self._fijar_dest_dh(pgp.leer_texto(ruta), os.path.basename(ruta))
        except protocolo.ErrorProtocolo as exc:
            self.log_emisor.error(str(exc))
            messagebox.showerror("Parametros DH rechazados", str(exc))
        except Exception as exc:  # noqa: BLE001
            self.log_emisor.error(f"Archivo invalido: {exc}")
            messagebox.showerror("Error", str(exc))

    def generar_paquete(self):
        cifrar = self.var_cifrar.get()
        firmar = self.var_firmar.get()

        if not cifrar and not firmar:
            messagebox.showwarning(
                "Sin servicios", "Selecciona al menos un servicio: cifrado, firma, o ambos."
            )
            return
        if firmar and (not self.mi_llave or not self.mi_llave.private_key):
            messagebox.showerror(
                "Falta tu llave", "Para firmar debes cargar tu llave privada en la pestania 1."
            )
            return
        if cifrar and not self.dest_dh:
            messagebox.showerror(
                "Falta el destinatario",
                "Para cifrar debes descargar la llave publica .asc del destinatario y "
                "sus parametros Diffie-Hellman verificados.",
            )
            return

        mensaje = self.txt_mensaje.get("1.0", tk.END).rstrip("\n").encode("utf-8")
        if not mensaje:
            messagebox.showwarning("Mensaje vacio", "Escribe el mensaje a proteger.")
            return

        self.log_emisor.limpiar()
        self.log_emisor.titulo("PROCESO EN EL EMISOR")
        self.log_emisor.info(f"Mensaje en claro: {len(mensaje)} bytes")

        try:
            paquete = protocolo.construir_paquete(
                mensaje=mensaje,
                confidencialidad=cifrar,
                firma=firmar,
                llave_emisor=self.mi_llave,
                dh_destinatario=self.dest_dh,
                uid_destinatario=self.dest_llave.uid if self.dest_llave else "",
                key_id_destinatario=self.dest_llave.key_id if self.dest_llave else "",
            )
        except (protocolo.ErrorProtocolo, motor.ErrorMotor) as exc:
            self.log_emisor.error(str(exc))
            messagebox.showerror("Error", str(exc))
            return

        if cifrar:
            self.log_emisor.ok("CONFIDENCIALIDAD: AES-128-CBC con K e IV acordados por Diffie-Hellman")
        else:
            self.log_emisor.info("Sin confidencialidad: el contenido va en claro.")
        if firmar:
            self.log_emisor.ok(
                "AUTENTICACION + INTEGRIDAD + NO REPUDIO: firma RSA sobre SHA-256(m)"
            )
        else:
            self.log_emisor.info("Sin firma: no hay autenticacion, integridad ni no repudio.")
        for linea in paquete.get("traza_emisor", []):
            self.log_emisor.paso(linea)

        ruta = filedialog.asksaveasfilename(
            title="Guardar el paquete para subirlo al Drive",
            defaultextension=".json",
            filetypes=[("Paquete criptografico", "*.json")],
        )
        if not ruta:
            self.log_emisor.info("Guardado cancelado.")
            return
        protocolo.guardar_json(ruta, paquete)
        self.log_emisor.escribir("")
        self.log_emisor.ok(f"Paquete guardado: {ruta}")
        self.log_emisor.paso("El archivo NO contiene ninguna exponente privada de Diffie-Hellman")
        self.log_emisor.paso("ni copia de la llave publica del firmante: el receptor debe")
        self.log_emisor.paso("descargarla de la pagina web del autor para poder verificar.")
        messagebox.showinfo("Listo", f"Paquete generado:\n{ruta}\n\nYa puedes subirlo al Drive.")

    # ==================================================================
    # PESTANIA 3 - Receptor
    # ==================================================================
    def _construir_receptor(self):
        marco = ttk.Frame(self.tab_receptor, padding=12)
        marco.pack(fill=tk.BOTH, expand=True)

        sup = ttk.Frame(marco)
        sup.pack(fill=tk.X)

        arch = ttk.LabelFrame(sup, text=" 1. Archivos descargados de la nube (x, y, z) ", padding=10)
        arch.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Button(arch, text="Seleccionar archivos", command=self.cargar_paquetes).pack(anchor=tk.W)
        ttk.Button(arch, text="Vaciar lista", command=self.vaciar_paquetes).pack(anchor=tk.W, pady=3)
        self.lista_paquetes = tk.Listbox(arch, height=6, font=("Consolas", 9))
        self.lista_paquetes.pack(fill=tk.BOTH, expand=True, pady=4)

        llav = ttk.LabelFrame(
            sup, text=" 2. Llavero: llaves publicas de los posibles autores ", padding=10
        )
        llav.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        fila = ttk.Frame(llav)
        fila.pack(fill=tk.X)
        self.url_autor = ttk.Entry(fila)
        self.url_autor.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(fila, text="Descargar de la web", command=self.agregar_autor_web).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(llav, text="Agregar desde archivo local .asc", command=self.agregar_autor_local).pack(
            anchor=tk.W, pady=3
        )
        self.lista_llavero = tk.Listbox(llav, height=6, font=("Consolas", 9))
        self.lista_llavero.pack(fill=tk.BOTH, expand=True, pady=4)

        acc = ttk.Frame(marco)
        acc.pack(fill=tk.X, pady=8)
        self.lbl_receptor_id = ttk.Label(acc, text="Sin llave privada cargada", foreground=COLOR_ERR)
        self.lbl_receptor_id.pack(side=tk.LEFT)
        ttk.Button(
            acc,
            text="Descifrar, verificar e identificar al autor de cada archivo",
            command=self.analizar,
        ).pack(side=tk.RIGHT)

        caja = ttk.LabelFrame(marco, text=" Resultados ", padding=8)
        caja.pack(fill=tk.BOTH, expand=True)
        self.log_receptor = Bitacora(caja, alto=16)
        self.log_receptor.info(
            "Carga los archivos de la nube, arma el llavero con las llaves publicas "
            "descargadas de las paginas web y pulsa el boton."
        )

    def cargar_paquetes(self):
        rutas = filedialog.askopenfilenames(
            title="Archivos descargados del Drive",
            filetypes=[("Paquetes criptograficos", "*.json"), ("Todos", "*.*")],
        )
        for ruta in rutas:
            try:
                datos = protocolo.cargar_json(ruta)
            except (OSError, json.JSONDecodeError) as exc:
                self.log_receptor.error(f"{os.path.basename(ruta)}: no es JSON valido ({exc})")
                continue
            self.paquetes.append({"nombre": os.path.basename(ruta), "datos": datos})
            self.lista_paquetes.insert(tk.END, os.path.basename(ruta))

    def vaciar_paquetes(self):
        self.paquetes.clear()
        self.lista_paquetes.delete(0, tk.END)

    def _agregar_al_llavero(self, texto: str, origen: str):
        llave = pgp.load_public_key(texto)
        for existente in self.llavero:
            if existente.fingerprint == llave.fingerprint:
                messagebox.showinfo("Ya estaba", f"{llave.uid} ya esta en el llavero.")
                return
        self.llavero.append(llave)
        self.lista_llavero.insert(tk.END, f"{llave.short_id()}  {llave.uid}")
        self.log_receptor.ok(f"Al llavero: {llave.uid} ({llave.short_id()}) desde {origen}")
        self.log_receptor.paso(f"Huella: {llave.pretty_fingerprint()}")

    def agregar_autor_web(self):
        url = self.url_autor.get().strip()
        if not url:
            messagebox.showwarning("Falta la URL", "Escribe la URL de la llave publica .asc del autor.")
            return
        try:
            self._agregar_al_llavero(descargar_texto(url), f"la web ({url})")
        except Exception as exc:  # noqa: BLE001
            self.log_receptor.error(f"No se pudo agregar la llave: {exc}")
            messagebox.showerror("Error", str(exc))

    def agregar_autor_local(self):
        rutas = filedialog.askopenfilenames(
            filetypes=[("Llaves OpenPGP", "*.asc"), ("Todos", "*.*")]
        )
        for ruta in rutas:
            try:
                self._agregar_al_llavero(pgp.leer_texto(ruta), os.path.basename(ruta))
            except (pgp.PGPError, OSError) as exc:
                self.log_receptor.error(f"{os.path.basename(ruta)}: {exc}")

    def analizar(self):
        if not self.paquetes:
            messagebox.showwarning("Sin archivos", "Carga primero los archivos de la nube.")
            return

        self.log_receptor.limpiar()
        self.log_receptor.titulo("DESCIFRADO Y VERIFICACION EN EL RECEPTOR")
        if self.mi_llave:
            self.log_receptor.info(f"Mi identidad: {self.mi_llave.uid} ({self.mi_llave.short_id()})")
        self.log_receptor.info(f"Llavero: {len(self.llavero)} llave(s) publica(s) cargada(s)")

        for entrada in self.paquetes:
            res = protocolo.analizar_paquete(
                entrada["datos"], entrada["nombre"], self.mi_llave, self.llavero
            )
            self._mostrar_resultado(res)

        self.log_receptor.escribir("")
        self.log_receptor.escribir("-" * 72)
        self.log_receptor.info("Analisis terminado.")

    def _mostrar_resultado(self, res: protocolo.Resultado):
        log = self.log_receptor
        log.escribir("")
        log.escribir("-" * 72)
        log.escribir(f"ARCHIVO: {res.archivo}", "titulo")

        if not res.formato_ok:
            for problema in res.problemas:
                log.error(problema)
            log.info("Este archivo no fue generado por esta practica; no hay nada que verificar.")
            return

        servicios = []
        if res.confidencialidad_pedida:
            servicios.append("confidencialidad")
        if res.firma_pedida:
            servicios.append("firma")
        log.info(f"Servicios declarados en el paquete: {', '.join(servicios) or 'ninguno'}")

        for paso in res.pasos:
            log.paso(paso)

        # Confidencialidad
        if res.confidencialidad_pedida:
            if res.descifrado_ok:
                log.ok("CONFIDENCIALIDAD: descifrado AES-CBC correcto con K e IV de Diffie-Hellman.")
            else:
                log.error("CONFIDENCIALIDAD: no se pudo descifrar.")

        # Autenticacion / integridad / no repudio
        if res.firma_pedida:
            if res.firma_ok and res.autor is not None:
                log.ok(f"AUTENTICACION: el autor es {res.autor.uid} ({res.autor.short_id()})")
                log.paso(f"Verificado con la llave publica {res.autor.pretty_fingerprint()}")
                log.ok("INTEGRIDAD: el SHA-256 recibido coincide con el firmado. Nada fue alterado.")
                log.ok("NO REPUDIO: solo esa llave privada pudo generar esta firma.")
                if res.emisor_declarado and res.emisor_declarado != res.autor.uid:
                    log.error(
                        f"AVISO: el paquete DECIA venir de '{res.emisor_declarado}', pero la "
                        f"firma demuestra que el autor real es '{res.autor.uid}'."
                    )
            elif res.firma_evaluada:
                log.error("VERIFICACION FALLIDA: la firma no verifica con ninguna llave del llavero.")
                log.error("INTEGRIDAD COMPROMETIDA o AUTOR DESCONOCIDO.")
                if res.emisor_declarado:
                    log.paso(
                        f"El archivo dice venir de '{res.emisor_declarado}', pero eso es un "
                        "simple texto: no se puede creer sin una firma valida."
                    )
            else:
                log.error(
                    "VERIFICACION NO CONCLUIDA: el descifrado fallo, asi que no se pudo "
                    "recuperar el mensaje para comprobar su firma."
                )
                log.error(
                    "INTEGRIDAD COMPROMETIDA: el archivo fue alterado en la nube "
                    "(el criptograma ya no corresponde a lo que se cifro)."
                )
                if res.emisor_declarado:
                    log.paso(
                        f"El archivo dice venir de '{res.emisor_declarado}', pero eso es un "
                        "simple texto: no se puede creer sin una firma valida."
                    )
        else:
            log.info("Sin firma: este archivo no permite saber quien lo escribio.")

        for problema in res.problemas:
            log.error(problema)

        if res.mensaje is not None and (res.firma_ok or not res.firma_pedida):
            log.escribir("")
            log.escribir("CONTENIDO DEL MENSAJE:", "titulo")
            log.escribir(res.texto())
        elif res.mensaje is not None:
            log.escribir("")
            log.escribir("CONTENIDO (NO CONFIABLE, la firma no verifico):", "titulo")
            log.escribir(res.texto())
        else:
            log.escribir("")
            log.error("No hay contenido legible: el archivo esta alterado.")

    # ==================================================================
    # PESTANIA 4 - Referencias
    # ==================================================================
    def _construir_referencias(self):
        marco = ttk.Frame(self.tab_refs, padding=12)
        marco.pack(fill=tk.BOTH, expand=True)
        texto = scrolledtext.ScrolledText(marco, font=("Consolas", 9), wrap=tk.WORD)
        texto.pack(fill=tk.BOTH, expand=True)
        texto.insert(tk.END, REFERENCIAS)
        texto.config(state=tk.DISABLED)


REFERENCIAS = """\
ALGORITMOS IMPLEMENTADOS Y SUS REFERENCIAS
==========================================

1. Diffie-Hellman  (confidencialidad: acuerdo de K e IV)
   - W. Diffie y M. Hellman, "New Directions in Cryptography", IEEE Transactions
     on Information Theory, vol. IT-22, no. 6, 1976.
   - RFC 3526 sec 3, "More MODP Diffie-Hellman groups for IKE": grupo de 2048
     bits (Group 14), primo p y generador g = 2.  Implementado en motor.py.
   - Se hacen DOS intercambios independientes: uno deriva la llave K de AES y
     otro deriva el IV, tal como muestra el diagrama del enunciado.
   - Derivacion de llave: SHA-256 del secreto compartido, truncado a 16 bytes
     (NIST SP 800-56A rev 3, sec 5.8: "Key Derivation Methods").
   - El intercambio es AUTENTICADO: los valores publicos Kb y Kd de cada persona
     van firmados con su llave RSA, asi que un tercero no puede sustituirlos
     (Menezes, van Oorschot y Vanstone, "Handbook of Applied Cryptography",
     cap. 12 sec 12.6, ataque de hombre en medio).

2. AES en modo CBC  (confidencialidad del mensaje)
   - NIST FIPS 197, "Advanced Encryption Standard".
   - NIST SP 800-38A sec 6.2, modo de operacion CBC.
   - Relleno PKCS#7, RFC 5652 sec 6.3.
   - Implementacion reutilizada: pyca/cryptography,
     cryptography.hazmat.primitives.ciphers (Cipher, algorithms.AES, modes.CBC)
     y cryptography.hazmat.primitives.padding.PKCS7.
     https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

3. SHA-256  (integridad)
   - NIST FIPS 180-4, "Secure Hash Standard".
   - Implementacion reutilizada: modulo hashlib de la biblioteca estandar de
     Python (enlaza con OpenSSL).

4. Firma digital RSA  (autenticacion, integridad y no repudio)
   - R. Rivest, A. Shamir y L. Adleman, "A Method for Obtaining Digital
     Signatures and Public-Key Cryptosystems", CACM, 1978.
   - RFC 8017 (PKCS #1 v2.2) sec 8.2 "RSASSA-PKCS1-v1_5" y sec 9.2
     "EMSA-PKCS1-v1_5": se firma el hash SHA-256 del mensaje en claro.
   - Implementacion reutilizada: pyca/cryptography, metodos sign() y verify()
     con padding.PKCS1v15() y utils.Prehashed(SHA256).
     https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

5. Lectura de llaves OpenPGP (.asc)  -  modulo pgp.py, Python puro
   - RFC 4880, "OpenPGP Message Format":
       sec 3.2   Multiprecision Integers (MPI)
       sec 3.7   String-to-Key (S2K): Simple, Salted e Iterated+Salted
       sec 4.2   Cabeceras de paquete, formatos antiguo y nuevo
       sec 5.5.2 Public-Key packet: version, algoritmo, MPIs n y e
       sec 5.5.3 Secret-Key packet: material d, p, q, u cifrado en modo CFB
       sec 6.1   CRC-24 del ASCII armor
       sec 6.2   ASCII armor
       sec 9.1   Algoritmos de llave publica    sec 9.2  Algoritmos simetricos
       sec 12.2  Huella digital v4 = SHA-1(0x99 || longitud || cuerpo)
   - Los parametros CRT (dmp1, dmq1, iqmp) se recalculan con las funciones
     rsa_crt_dmp1 / rsa_crt_dmq1 / rsa_crt_iqmp de pyca/cryptography, porque
     OpenPGP guarda u = p^-1 mod q y PKCS#1 espera iqmp = q^-1 mod p.

6. Descarga de las llaves publicas desde la pagina web
   - Biblioteca requests, https://requests.readthedocs.io/

DECISIONES DE DISENIO QUE CONVIENE EXPLICAR EN EL VIDEO
=======================================================
* La llave con la que se VERIFICA una firma nunca viaja dentro del paquete: se
  descarga de la pagina web del autor. Si viajara dentro, cualquiera podria
  firmar con una llave propia y la verificacion pasaria siempre.
* Ninguna exponente privada de Diffie-Hellman aparece en el archivo. Solo
  viajan los valores publicos efimeros Ka y Kc.
* El campo "emisor_declarado_no_confiable" es solo una pista para ordenar
  archivos. La autoria se decide probando la firma contra cada llave publica
  del llavero: gana la que verifica.
* El par Diffie-Hellman estatico de cada persona se deriva de su propia llave
  RSA privada, asi que no hay archivos de estado que perder: basta volver a
  cargar el .asc para recuperar los mismos Kb y Kd publicados.
"""


if __name__ == "__main__":
    AplicacionHibrida().mainloop()
