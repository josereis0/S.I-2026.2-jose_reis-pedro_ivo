"""
SERVIDOR
Trabalho de Segurança da Informação 

Responsabilidades deste processo:
1. Gerar a base e o resto da divisão(parametros publicos p e g) do diffie hellman

2. comunica os parametros publicos p e g para o cliente

3. recebe a chave publica do cliente, gera a propria chave publica e devolve para o cliente, 
ambos calculam o segredo compartilhado e derivam uma chave AES para cifrar/decifrar dados.

4. Recebe dados cifrados do cliente e grava no banco de dados (sqlite3), sem nunca ver os dados reais da comunicação.
Rode com: python3 server.py

rodando  em http://127.0.0.1:5000

(futuramente podemos fazer o deploy em um servidor real, mas por enquanto é só local mesmo)


"""

import os
import time
import hmac
import hashlib
import sqlite3
import secrets

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# Critérios de expiração da sessão (Seção 6.4)
LIMITE_MENSAGENS = 100
LIMITE_TEMPO_SEGUNDOS = 60 * 60  # 60 minutos

# ---------------------------------------------------------------------
# Parâmetros públicos do grupo DH, gerados uma vez ao iniciar o servidor.
# Em produção isso poderia usar um grupo padronizado (RFC 3526/7919)
# em vez de gerar na hora, para evitar o custo de gerar um primo novo.
# ---------------------------------------------------------------------
print("Gerando parâmetros DH (pode levar alguns segundos)...")
PARAMETROS = dh.generate_parameters(generator=2, key_size=2048)
NUMEROS_PARAMETROS = PARAMETROS.parameter_numbers()
print("Parâmetros prontos.")

# Sessões ativas: session_id -> {chave_aes, chave_hmac, criada_em, mensagens_processadas}
SESSOES = {}


def sessao_esta_expirada(session_id: str) -> tuple[bool, str]:
    """Verifica se a sessão ultrapassou o limite de 60 minutos ou 100 mensagens."""
    if session_id not in SESSOES:
        return True, "Sessão inexistente"

    sessao = SESSOES[session_id]
    tempo_decorrido = time.time() - sessao["criada_em"]

    if tempo_decorrido > LIMITE_TEMPO_SEGUNDOS:
        return True, f"Tempo limite atingido ({int(tempo_decorrido)}s decorridos)"

    if sessao["mensagens_processadas"] >= LIMITE_MENSAGENS:
        return True, f"Limite de mensagens atingido ({sessao['mensagens_processadas']} mensagens)"

    return False, ""


def derivar_chaves(segredo_compartilhado: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derivação via HKDF-SHA256 (64 bytes de saída):
    - Chave 1 (primeiros 32 bytes): AES-256
    - Chave 2 (últimos 32 bytes): HMAC-SHA-256
    """
    saida = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"chave-aes-dh-seguranca-info",
    ).derive(segredo_compartilhado)
    return saida[:32], saida[32:]


def verificar_mac_e_decifrar(chave_aes: bytes, chave_hmac: bytes, iv: bytes, cifrado: bytes, mac_recebido: bytes) -> str:
    """
    Regra estrita: Verifica o MAC antes de qualquer decifração.
    Se divergente, descarta imediatamente.
    """
    conteudo = iv + cifrado
    mac_esperado = hmac.new(chave_hmac, conteudo, hashlib.sha256).digest()

    if not hmac.compare_digest(mac_recebido, mac_esperado):
        print("[SERVIDOR - SEGURANÇA] MAC inválido! Integridade violada. Pacote descartado.")
        raise ValueError("MAC inválido: mensagem corrompida ou adulterada.")

    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dados_padded = decryptor.update(cifrado) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    texto_claro = unpadder.update(dados_padded) + unpadder.finalize()
    return texto_claro.decode("utf-8")


def criar_banco():
    conn = sqlite3.connect("dados_seguros.db")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            iv BLOB NOT NULL,
            cifrado BLOB NOT NULL,
            mac BLOB NOT NULL
        )
        """
    )
    conn.commit()
    return conn


# ENDPOINT 1: cliente pede os parâmetros públicos do grupo (p, g)

@app.route("/dh/parametros", methods=["GET"])
def obter_parametros():
    return jsonify({
        "p": hex(NUMEROS_PARAMETROS.p),
        "g": NUMEROS_PARAMETROS.g,
    })


# ENDPOINT 2: cliente envia sua chave pública, servidor devolve a dele
# e ambos ficam com o mesmo segredo compartilhado.

@app.route("/dh/trocar-chave", methods=["POST"])
def trocar_chave():
    dados = request.get_json()
    chave_publica_cliente_y = int(dados["chave_publica"], 16)
    salt_cliente = bytes.fromhex(dados["salt"])

    # Reconstrói a chave pública do cliente a partir do número recebido
    numeros_publicos_cliente = dh.DHPublicNumbers(
        chave_publica_cliente_y, NUMEROS_PARAMETROS
    )
    chave_publica_cliente = numeros_publicos_cliente.public_key()

    # Servidor gera seu próprio par de chaves para esta sessão
    chave_privada_servidor = PARAMETROS.generate_private_key()
    chave_publica_servidor = chave_privada_servidor.public_key()

    # Calcula o segredo compartilhado e deriva as chaves AES e HMAC da sessão (64 bytes)
    segredo = chave_privada_servidor.exchange(chave_publica_cliente)
    chave_aes, chave_hmac = derivar_chaves(segredo, salt_cliente)

    # Guarda as chaves e inicializa os contadores de tempo e mensagens
    session_id = secrets.token_hex(16)
    SESSOES[session_id] = {
        "chave_aes": chave_aes,
        "chave_hmac": chave_hmac,
        "criada_em": time.time(),
        "mensagens_processadas": 0
    }

    y_servidor = chave_publica_servidor.public_numbers().y

    return jsonify({
        "session_id": session_id,
        "chave_publica": hex(y_servidor),
    })


# ENDPOINT 3: cliente envia dado já cifrado (com a chave da sessão)
# para ser gravado no banco.

@app.route("/usuarios", methods=["POST"])
def salvar_usuario():
    dados = request.get_json()
    session_id = dados.get("session_id")

    # Verifica expiração de sessão antes de processar
    expirada, motivo = sessao_esta_expirada(session_id)
    if expirada:
        return jsonify({"erro": f"Sessão expirada: {motivo}"}), 401

    chaves = SESSOES[session_id]
    nome = dados["nome"]
    iv = bytes.fromhex(dados["iv"])
    cifrado = bytes.fromhex(dados["cifrado"])
    mac_recebido = bytes.fromhex(dados["mac"])

    # ORDEM CORRETA: Verificar o MAC antes de qualquer manipulação ou decifração
    conteudo = iv + cifrado
    mac_esperado = hmac.new(chaves["chave_hmac"], conteudo, hashlib.sha256).digest()

    if not hmac.compare_digest(mac_recebido, mac_esperado):
        print(f"[SERVIDOR] MAC adulterado recebido de {session_id}! Pacote descartado.")
        return jsonify({"erro": "MAC inválido: pacote corrompido ou adulterado descartado"}), 403

    # Incrementa a contagem de mensagens processadas
    chaves["mensagens_processadas"] += 1
    print(f"[SERVIDOR] Sessão {session_id[:8]}... | Mensagem #{chaves['mensagens_processadas']}/{LIMITE_MENSAGENS}")

    conn = criar_banco()
    cur = conn.execute(
        "INSERT INTO usuarios (nome, iv, cifrado, mac) VALUES (?, ?, ?, ?)",
        (nome, iv, cifrado, mac_recebido),
    )
    conn.commit()
    novo_id = cur.lastrowid
    conn.close()

    return jsonify({"id": novo_id, "status": "salvo_com_sucesso"})


# ---------------------------------------------------------------------
# ENDPOINT 4: cliente busca o dado cifrado de volta (descriptografa
# localmente, o servidor nunca vê o dado em texto claro).
# ---------------------------------------------------------------------
@app.route("/usuarios/<int:usuario_id>", methods=["GET"])
def ler_usuario(usuario_id):
    session_id = request.args.get("session_id")

    # Verifica expiração de sessão antes de processar
    expirada, motivo = sessao_esta_expirada(session_id)
    if expirada:
        return jsonify({"erro": f"Sessão expirada: {motivo}"}), 401

    chaves = SESSOES[session_id]
    chaves["mensagens_processadas"] += 1
    print(f"[SERVIDOR] Sessão {session_id[:8]}... | Mensagem #{chaves['mensagens_processadas']}/{LIMITE_MENSAGENS}")

    conn = criar_banco()
    cur = conn.execute(
        "SELECT nome, iv, cifrado, mac FROM usuarios WHERE id = ?",
        (usuario_id,),
    )
    linha = cur.fetchone()
    conn.close()

    if linha is None:
        return jsonify({"erro": "não encontrado"}), 404

    nome, iv, cifrado, mac = linha
    return jsonify({
        "nome": nome,
        "iv": iv.hex(),
        "cifrado": cifrado.hex(),
        "mac": mac.hex(),
    })


if __name__ == "__main__":
    criar_banco()
    app.run(host="127.0.0.1", port=5000, debug=False)