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
import sqlite3
import secrets


from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# ---------------------------------------------------------------------
# Parâmetros públicos do grupo DH, gerados uma vez ao iniciar o servidor.
# Em produção isso poderia usar um grupo padronizado (RFC 3526/7919)
# em vez de gerar na hora, para evitar o custo de gerar um primo novo.
# ---------------------------------------------------------------------
print("Gerando parâmetros DH (pode levar alguns segundos)...")
PARAMETROS = dh.generate_parameters(generator=2, key_size=2048)
NUMEROS_PARAMETROS = PARAMETROS.parameter_numbers()
print("Parâmetros prontos.")

# Sessões ativas: session_id -> chave AES derivada para aquele cliente
SESSOES = {}


def derivar_chave_aes(segredo_compartilhado: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chave-aes-dh-seguranca-info",
    ).derive(segredo_compartilhado)


def criar_banco():
    conn = sqlite3.connect("dados_seguros.db")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            dado_nonce BLOB NOT NULL,
            dado_cifrado BLOB NOT NULL
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

    # Reconstrói a chave pública do cliente a partir do número recebido
    numeros_publicos_cliente = dh.DHPublicNumbers(
        chave_publica_cliente_y, NUMEROS_PARAMETROS
    )
    chave_publica_cliente = numeros_publicos_cliente.public_key()

    # Servidor gera seu próprio par de chaves para esta sessão
    chave_privada_servidor = PARAMETROS.generate_private_key()
    chave_publica_servidor = chave_privada_servidor.public_key()

    # Calcula o segredo compartilhado e deriva a chave AES da sessão
    segredo = chave_privada_servidor.exchange(chave_publica_cliente)
    chave_aes = derivar_chave_aes(segredo)

    # Guarda a chave associada a um id de sessão (nunca é enviada de volta)
    session_id = secrets.token_hex(16)
    SESSOES[session_id] = chave_aes

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
    session_id = dados["session_id"]

    if session_id not in SESSOES:
        return jsonify({"erro": "sessão inválida ou expirada"}), 401

    nome = dados["nome"]
    nonce = bytes.fromhex(dados["nonce"])
    cifrado = bytes.fromhex(dados["cifrado"])

    conn = criar_banco()
    cur = conn.execute(
        "INSERT INTO usuarios (nome, dado_nonce, dado_cifrado) VALUES (?, ?, ?)",
        (nome, nonce, cifrado),
    )
    conn.commit()
    novo_id = cur.lastrowid
    conn.close()

    return jsonify({"id": novo_id})


# ---------------------------------------------------------------------
# ENDPOINT 4: cliente busca o dado cifrado de volta (descriptografa
# localmente, o servidor nunca vê o dado em texto claro).
# ---------------------------------------------------------------------
@app.route("/usuarios/<int:usuario_id>", methods=["GET"])
def ler_usuario(usuario_id):
    session_id = request.args.get("session_id")
    if session_id not in SESSOES:
        return jsonify({"erro": "sessão inválida ou expirada"}), 401

    conn = criar_banco()
    cur = conn.execute(
        "SELECT nome, dado_nonce, dado_cifrado FROM usuarios WHERE id = ?",
        (usuario_id,),
    )
    linha = cur.fetchone()
    conn.close()

    if linha is None:
        return jsonify({"erro": "não encontrado"}), 404

    nome, nonce, cifrado = linha
    return jsonify({
        "nome": nome,
        "nonce": nonce.hex(),
        "cifrado": cifrado.hex(),
    })


if __name__ == "__main__":
    serve(app, host="127.0.0.1", port=5000)
