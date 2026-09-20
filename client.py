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
import time
import hmac
import hashlib
import requests

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVIDOR = "http://127.0.0.1:5000"

# Critérios de expiração da sessão (Seção 6.4)
INTERVALO_TEMPO_SEGUNDOS = (30 * 60, 60 * 60)  # 30 a 60 minutos


class ControleSessao:
    """Monitora o estado da sessão e sinaliza a necessidade de renovação."""
    def __init__(self, session_id: str, chave_aes: bytes, chave_hmac: bytes, parametros_dh, limite_mensagens: int):
        self.session_id = session_id
        self.chave_aes = chave_aes
        self.chave_hmac = chave_hmac
        self.parametros_dh = parametros_dh
        self.limite_mensagens = limite_mensagens
        self.inicio = time.time()
        self.contador_mensagens = 0

    def registrar_uso(self):
        self.contador_mensagens += 1

    def precisa_renovar(self) -> bool:
        """Verifica se atingiu o limite aleatório de mensagens ou de tempo decorrido."""
        if self.contador_mensagens >= self.limite_mensagens:
            return True
        if (time.time() - self.inicio) > INTERVALO_TEMPO_SEGUNDOS[1]:
            return True
        return False


def derivar_chaves(segredo_compartilhado: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """
    Deriva 64 bytes via HKDF-SHA256:
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


def cifrar_com_mac(chave_aes: bytes, chave_hmac: bytes, texto_claro: str) -> dict:
    """
    Encrypt-then-MAC:
    1. Cifra com AES-256-CBC (Chave 1)
    2. Calcula HMAC-SHA256 sobre (IV + Cifrado) (Chave 2)
    """
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    dados_padded = padder.update(texto_claro.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(dados_padded) + encryptor.finalize()

    mac = hmac.new(chave_hmac, iv + cifrado, hashlib.sha256).digest()
    return {
        "iv": iv.hex(),
        "cifrado": cifrado.hex(),
        "mac": mac.hex()
    }


def verificar_mac_e_decifrar(chave_aes: bytes, chave_hmac: bytes, iv: bytes, cifrado: bytes, mac_recebido: bytes) -> str:
    """
    Regra do edital:
    1. O receptor recalcula o MAC usando a Chave 2.
    2. Se os MACs não baterem, o pacote é descartado imediatamente sem decifrar.
    3. Só decifra com AES-256 (Chave 1) se o MAC for válido.
    """
    conteudo = iv + cifrado
    mac_esperado = hmac.new(chave_hmac, conteudo, hashlib.sha256).digest()

    if not hmac.compare_digest(mac_recebido, mac_esperado):
        print("[CLIENTE - SEGURANÇA] MAC inválido! Integridade violada. Descartando mensagem.")
        raise ValueError("MAC inválido: a mensagem foi adulterada e descartada.")

    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dados_padded = decryptor.update(cifrado) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    texto_claro = unpadder.update(dados_padded) + unpadder.finalize()
    return texto_claro.decode("utf-8")


def realizar_handshake(parametros_existentes=None) -> ControleSessao:
    """Executa o handshake DHE + HKDF para criar ou renovar a sessão."""
    # 1. Obtém ou reutiliza os parâmetros do grupo DH
    if parametros_existentes is None:
        resp = requests.get(f"{SERVIDOR}/dh/parametros")
        resp.raise_for_status()
        dados_params = resp.json()
        p = int(dados_params["p"], 16)
        g = dados_params["g"]
        parametros = dh.DHParameterNumbers(p, g).parameters()
    else:
        parametros = parametros_existentes

    # 2. Gera novo par efêmero do cliente e novo salt
    chave_privada_cliente = parametros.generate_private_key()
    chave_publica_cliente = chave_privada_cliente.public_key()
    y_cliente = chave_publica_cliente.public_numbers().y
    salt_cliente = os.urandom(16)

    # 3. Envia pública e salt ao servidor
    resp = requests.post(
        f"{SERVIDOR}/dh/trocar-chave",
        json={
            "chave_publica": hex(y_cliente),
            "salt": salt_cliente.hex()
        },
    )
    resp.raise_for_status()
    resposta = resp.json()
    session_id = resposta["session_id"]
    y_servidor = int(resposta["chave_publica"], 16)
    limite_mensagens = resposta.get("limite_mensagens", 3)

    # 4. Deriva novas Chave 1 (AES) e Chave 2 (HMAC)
    numeros_publicos_servidor = dh.DHPublicNumbers(y_servidor, parametros.parameter_numbers())
    chave_publica_servidor = numeros_publicos_servidor.public_key()
    segredo = chave_privada_cliente.exchange(chave_publica_servidor)
    chave_aes, chave_hmac = derivar_chaves(segredo, salt_cliente)

    return ControleSessao(session_id, chave_aes, chave_hmac, parametros, limite_mensagens)


def enviar_dado_seguro(sessao: ControleSessao, nome: str, dado: str) -> tuple[ControleSessao, int]:
    """
    Envia dado com renovação automática prévia se o limite foi atingido.
    Também renova e reenvia caso o servidor rejeite por expiração (401).
    """
    # Verificação preventiva: renova antes de enviar se a sessão local venceu
    if sessao.precisa_renovar():
        print(f"\n[RENOVAÇÃO] Limite de mensagens/tempo atingido ({sessao.contador_mensagens}/{sessao.limite_mensagens})!")
        print("[RENOVAÇÃO] Executando novo handshake automático com o servidor...")
        sessao = realizar_handshake(sessao.parametros_dh)
        print(f"[RENOVAÇÃO] Handshake concluído. Nova sessão: {sessao.session_id[:8]}... | Novo limite sorteado: {sessao.limite_mensagens}\n")

    pacote = cifrar_com_mac(sessao.chave_aes, sessao.chave_hmac, dado)
    
    resp = requests.post(
        f"{SERVIDOR}/usuarios",
        json={
            "session_id": sessao.session_id,
            "nome": nome,
            "iv": pacote["iv"],
            "cifrado": pacote["cifrado"],
            "mac": pacote["mac"],
        },
    )

    # Tratamento caso o servidor tenha expirado primeiro
    if resp.status_code == 401:
        print("\n[RENOVAÇÃO] Servidor retornou 401 (Sessão Expirada). Renovando handshake agora...")
        sessao = realizar_handshake(sessao.parametros_dh)
        return enviar_dado_seguro(sessao, nome, dado)

    resp.raise_for_status()
    sessao.registrar_uso()
    return sessao, resp.json()["id"]


def main():
    print("=== Cliente: iniciando troca de chaves com o servidor ===")
    
    # Handshake inicial
    sessao = realizar_handshake()
    print(f"Sessão inicial estabelecida: {sessao.session_id[:8]}... | Limite sorteado: {sessao.limite_mensagens}")
    print("Chaves de sessão derivadas localmente via HKDF.\n")

    # Demonstração: envia 6 mensagens em loop para disparar a renovação automática
    mensagens_teste = [
        "Mensagem 1: CPF 111.111.111-11",
        "Mensagem 2: CPF 222.222.222-22",
        "Mensagem 3: CPF 333.333.333-33",
        "Mensagem 4: CPF 444.444.444-44",
        "Mensagem 5: CPF 555.555.555-55",
        "Mensagem 6: CPF 666.666.666-66",
    ]

    for texto in mensagens_teste:
        sessao, user_id = enviar_dado_seguro(sessao, "Maria Silva", texto)
        print(f"[OK] Enviado id={user_id} | Sessão atual: {sessao.session_id[:8]}... | Uso: {sessao.contador_mensagens}/{sessao.limite_mensagens}")


if __name__ == "__main__":
    main()