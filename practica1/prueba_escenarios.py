"""
Prueba automatizada de los escenarios A-F del enunciado, sin interfaz grafica.

Uso:
    python prueba_escenarios.py CARPETA_DE_LLAVES

La carpeta debe contener alicia_pub.asc / alicia_priv.asc y lo mismo para
betito y candy. Las frases de paso se piden por consola (o se toman de las
variables de entorno PASS_ALICIA, PASS_BETITO, PASS_CANDY).

Sirve para comprobar que la implementacion funciona antes de grabar el video,
y para demostrar en clase que la suplantacion y la alteracion se detectan.
"""

import base64
import copy
import os
import sys

import pgp
import protocolo

VERDE, ROJO, GRIS, FIN = "\033[92m", "\033[91m", "\033[90m", "\033[0m"
fallos = 0


def check(condicion: bool, descripcion: str) -> None:
    global fallos
    if condicion:
        print(f"  {VERDE}PASA{FIN}  {descripcion}")
    else:
        fallos += 1
        print(f"  {ROJO}FALLA{FIN} {descripcion}")


def titulo(t: str) -> None:
    print(f"\n{'=' * 70}\n{t}\n{'=' * 70}")


def cargar(carpeta: str, nombre: str):
    pub = pgp.load_public_key(
        open(os.path.join(carpeta, f"{nombre}_pub.asc"), encoding="utf-8").read()
    )
    texto = open(os.path.join(carpeta, f"{nombre}_priv.asc"), encoding="utf-8").read()
    frase = os.environ.get(f"PASS_{nombre.upper()}")
    if frase is None and pgp.needs_passphrase(texto):
        import getpass

        frase = getpass.getpass(f"Frase de paso de {nombre}: ")
    priv = pgp.load_secret_key(texto, frase or "")
    return pub, priv


def main(carpeta: str) -> int:
    titulo("CARGA DE LLAVES OPENPGP")
    alicia_pub, alicia = cargar(carpeta, "alicia")
    betito_pub, betito = cargar(carpeta, "betito")
    candy_pub, candy = cargar(carpeta, "candy")
    for nombre, pub, priv in [
        ("Alicia", alicia_pub, alicia),
        ("Betito", betito_pub, betito),
        ("Candy", candy_pub, candy),
    ]:
        print(f"  {nombre}: {priv.uid}  keyid={priv.short_id()}  RSA-{priv.bits}")
        check(pub.fingerprint == priv.fingerprint, f"{nombre}: la publica y la privada son del mismo par")

    titulo("PUBLICACION DE PARAMETROS DIFFIE-HELLMAN (pagina web de Betito)")
    dhpub_betito = protocolo.construir_dhpub(betito)
    print(f"  Kb = {dhpub_betito['Kb_hex'][:48]}...")
    print(f"  Kd = {dhpub_betito['Kd_hex'][:48]}...")
    dh_verificado = protocolo.verificar_dhpub(dhpub_betito, betito_pub)
    check(True, "Alicia verifica la firma de los parametros DH de Betito con su .asc")

    # Hombre en medio: Candy sustituye Kb
    manipulado = copy.deepcopy(dhpub_betito)
    manipulado["Kb_hex"] = format(int(manipulado["Kb_hex"], 16) ^ 0xFF, "x")
    try:
        protocolo.verificar_dhpub(manipulado, betito_pub)
        check(False, "los parametros DH sustituidos deben rechazarse")
    except protocolo.ErrorProtocolo:
        check(True, "parametros DH sustituidos: RECHAZADOS (Diffie-Hellman autenticado)")

    titulo("A) Alicia cifra y firma un mensaje para Betito  ->  x.json")
    m_alicia = "Betito, la reunion es el viernes a las 7. -Alicia".encode("utf-8")
    x = protocolo.construir_paquete(
        mensaje=m_alicia,
        confidencialidad=True,
        firma=True,
        llave_emisor=alicia,
        dh_destinatario=dh_verificado,
        uid_destinatario=betito_pub.uid,
        key_id_destinatario=betito_pub.key_id,
    )
    for linea in x["traza_emisor"]:
        print(f"  {GRIS}{linea}{FIN}")
    check("dh_b_simulated" not in str(x), "el paquete NO contiene ninguna exponente privada DH")
    check("pub_cert" not in str(x), "el paquete NO contiene la llave publica del firmante")

    titulo("B) Candy cifra y firma un mensaje para Betito  ->  y.json")
    m_candy = "Betito, te dejo el reporte de la practica. -Candy".encode("utf-8")
    y = protocolo.construir_paquete(
        mensaje=m_candy,
        confidencialidad=True,
        firma=True,
        llave_emisor=candy,
        dh_destinatario=dh_verificado,
        uid_destinatario=betito_pub.uid,
        key_id_destinatario=betito_pub.key_id,
    )
    print(f"  {GRIS}{y['traza_emisor'][-1]}{FIN}")

    titulo("C) Candy duplica el archivo de Alicia y lo renombra  ->  z.json")
    z = copy.deepcopy(x)

    titulo("D) Betito descifra, verifica e identifica al autor de x, y, z")
    llavero = [alicia_pub, betito_pub, candy_pub]
    for nombre, paquete, esperado, texto in [
        ("x.json", x, alicia_pub, m_alicia),
        ("y.json", y, candy_pub, m_candy),
        ("z.json", z, alicia_pub, m_alicia),
    ]:
        r = protocolo.analizar_paquete(paquete, nombre, betito, llavero)
        autor = r.autor.uid if r.autor else "NINGUNO"
        print(f"  {nombre}: autor={autor}  contenido={r.texto()!r}")
        check(r.descifrado_ok, f"{nombre}: confidencialidad, descifrado correcto")
        check(r.firma_ok and r.autor is esperado, f"{nombre}: autenticacion, autor = {esperado.uid}")
        check(r.mensaje == texto, f"{nombre}: integridad, el contenido coincide con el original")

    titulo("D-bis) Candy intenta SUPLANTAR a Alicia")
    falso = protocolo.construir_paquete(
        mensaje=b"Betito, transfiereme el dinero. -Alicia",
        confidencialidad=True,
        firma=True,
        llave_emisor=candy,
        dh_destinatario=dh_verificado,
        uid_destinatario=betito_pub.uid,
        key_id_destinatario=betito_pub.key_id,
    )
    falso["emisor_declarado_no_confiable"] = alicia_pub.uid  # miente en el texto
    r = protocolo.analizar_paquete(falso, "falso.json", betito, llavero)
    print(f"  el archivo DICE venir de : {falso['emisor_declarado_no_confiable']}")
    print(f"  la firma demuestra que es: {r.autor.uid if r.autor else 'NINGUNO'}")
    check(r.autor is candy_pub, "la suplantacion se detecta: el autor real es Candy")

    titulo("E) Candy altera el archivo en la nube: falla la INTEGRIDAD")
    alterado = copy.deepcopy(x)
    crudo = bytearray(base64.b64decode(alterado["contenido_b64"]))
    crudo[5] ^= 0x01  # un solo bit
    alterado["contenido_b64"] = base64.b64encode(bytes(crudo)).decode()
    r = protocolo.analizar_paquete(alterado, "x.json (alterado)", betito, llavero)
    print(f"  problemas reportados: {r.problemas}")
    check(not r.integridad_ok, "un bit cambiado rompe la verificacion")
    check(bool(r.problemas), "el receptor explica por que fallo, sin caerse")

    titulo("E-bis) Candy altera solo el nombre del emisor declarado")
    mentira = copy.deepcopy(x)
    mentira["emisor_declarado_no_confiable"] = "Candy Lopez <candy@escom.ipn.mx>"
    r = protocolo.analizar_paquete(mentira, "x.json (renombrado)", betito, llavero)
    check(r.autor is alicia_pub, "cambiar el texto del emisor no engania: sigue siendo Alicia")

    titulo("F) Se restaura el archivo original: vuelve a verificar")
    r = protocolo.analizar_paquete(x, "x.json (restaurado)", betito, llavero)
    check(r.firma_ok and r.autor is alicia_pub, "verificacion correcta de nuevo")
    check(r.mensaje == m_alicia, "contenido intacto")

    titulo("SERVICIOS POR SEPARADO: uno de dos")
    solo_firma = protocolo.construir_paquete(
        mensaje=b"aviso publico firmado", confidencialidad=False, firma=True, llave_emisor=alicia
    )
    r = protocolo.analizar_paquete(solo_firma, "solo_firma.json", betito, llavero)
    check(r.firma_ok and not r.confidencialidad_pedida, "solo firma: autentica sin cifrar")

    solo_cifrado = protocolo.construir_paquete(
        mensaje=b"secreto anonimo",
        confidencialidad=True,
        firma=False,
        dh_destinatario=dh_verificado,
        uid_destinatario=betito_pub.uid,
        key_id_destinatario=betito_pub.key_id,
    )
    r = protocolo.analizar_paquete(solo_cifrado, "solo_cifrado.json", betito, llavero)
    check(
        r.descifrado_ok and not r.firma_pedida and r.mensaje == b"secreto anonimo",
        "solo cifrado: confidencial pero sin autor demostrable",
    )

    titulo("EL PAQUETE DE BETITO NO LO PUEDE ABRIR CANDY")
    r = protocolo.analizar_paquete(copy.deepcopy(x), "x.json", candy, llavero)
    check(not r.descifrado_ok, "Candy no puede descifrar lo que era para Betito")

    print()
    if fallos:
        print(f"{ROJO}{fallos} comprobacion(es) fallaron{FIN}")
    else:
        print(f"{VERDE}Todas las comprobaciones pasaron{FIN}")
    return 1 if fallos else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
