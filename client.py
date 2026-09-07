"""
CLIENTE
Trabalho de Segurança da Informação - Diffie-Hellman

Este processo é totalmente separado do servidor: só conversa com ele
por HTTP (poderia estar em outra máquina). Ele:

1. Busca as chaves públicas do diffie hellman no servidor (p e g).

2. Gera a chave privada  (privada nunca sai daqui).

3. Envia sua chave pública, recebe a do servidor e o id da sessão.
4. Calcula o segredo compartilhado -> deriva a mesma chave AES do servidor.
5. Cifra um dado sensível localmente e manda só o resultado cifrado.
6. Busca o dado de volta e descriptografa localmente.

Rode com: python3 client.py


"""

import os
import requests

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVIDOR = "http://127.0.0.1:5000"


def derivar_chave_aes(segredo_compartilhado: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chave-aes-dh-seguranca-info",
    ).derive(segredo_compartilhado)


def criptografar(chave_aes: bytes, texto_claro: str):
    aesgcm = AESGCM(chave_aes)
    nonce = os.urandom(12)
    cifrado = aesgcm.encrypt(nonce, texto_claro.encode("utf-8"), None)
    return nonce, cifrado


def descriptografar(chave_aes: bytes, nonce: bytes, cifrado: bytes) -> str:
    aesgcm = AESGCM(chave_aes)
    return aesgcm.decrypt(nonce, cifrado, None).decode("utf-8")


def main():
    print("=== Cliente: iniciando troca de chaves com o servidor ===")

    # 1) Busca os parâmetros públicos do grupo (p, g)
    resp = requests.get(f"{SERVIDOR}/dh/parametros")
    resp.raise_for_status()
    dados_params = resp.json()
    p = int(dados_params["p"], 16)
    g = dados_params["g"]

    numeros_parametros = dh.DHParameterNumbers(p, g)
    parametros = numeros_parametros.parameters()

    # 2) Gera seu próprio par de chaves dentro desse grupo
    chave_privada_cliente = parametros.generate_private_key()
    chave_publica_cliente = chave_privada_cliente.public_key()
    y_cliente = chave_publica_cliente.public_numbers().y

    # 3) Envia sua chave pública, recebe a do servidor + session_id
    resp = requests.post(
        f"{SERVIDOR}/dh/trocar-chave",
        json={"chave_publica": hex(y_cliente)},
    )
    resp.raise_for_status()
    resposta = resp.json()
    session_id = resposta["session_id"]
    y_servidor = int(resposta["chave_publica"], 16)

    numeros_publicos_servidor = dh.DHPublicNumbers(y_servidor, numeros_parametros)
    chave_publica_servidor = numeros_publicos_servidor.public_key()

    # 4) Calcula o segredo compartilhado -> mesma chave AES do servidor
    segredo = chave_privada_cliente.exchange(chave_publica_servidor)
    chave_aes = derivar_chave_aes(segredo)
    print(f"Sessão estabelecida: {session_id}")
    print("Chave AES da sessão derivada localmente (nunca trafegou na rede).\n")

    # 5) Cifra o dado sensível localmente e envia só o resultado cifrado
    nome = "Maria Silva"
    dado_sensivel = "CPF: 123.456.789-00"
    nonce, cifrado = criptografar(chave_aes, dado_sensivel)

    resp = requests.post(
        f"{SERVIDOR}/usuarios",
        json={
            "session_id": session_id,
            "nome": nome,
            "nonce": nonce.hex(),
            "cifrado": cifrado.hex(),
        },
    )
    resp.raise_for_status()
    usuario_id = resp.json()["id"]
    print(f"Dado enviado e gravado no banco do servidor (id={usuario_id}).")
    print("O servidor NUNCA viu o CPF em texto claro.\n")

    # 6) Busca o dado de volta e descriptografa localmente
    resp = requests.get(
        f"{SERVIDOR}/usuarios/{usuario_id}",
        params={"session_id": session_id},
    )
    resp.raise_for_status()
    linha = resp.json()
    dado_recebido = descriptografar(
        chave_aes, bytes.fromhex(linha["nonce"]), bytes.fromhex(linha["cifrado"])
    )
    print(f"Lido de volta do servidor -> nome: {linha['nome']}, dado: {dado_recebido}")


if __name__ == "__main__":
    main()
