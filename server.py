import socket
import threading
import sqlite3
import json
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import dh

from chat_cripto import (
    derivar_chaves,
    SessaoCripto,
    INTERVALO_MENSAGENS,
    INTERVALO_TEMPO_SEGUNDOS,
)

HOST = '127.0.0.1'
PORT = 5050

clientes_online = {}      # username -> socket
sessoes_clientes = {}      # socket -> SessaoCripto

print("[CRIPTOGRAFIA] Gerando parâmetros DH FFDH 2048-bit...")
PARAMETROS_DH = dh.generate_parameters(generator=2, key_size=2048)
NUMEROS_DH = PARAMETROS_DH.parameter_numbers()
print("[CRIPTOGRAFIA] Parâmetros DH prontos.")


def inicializar_banco():
    conexao = sqlite3.connect('chat_uabj.db')
    cursor = conexao.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mensagens_offline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            destinatario TEXT NOT NULL,
            remetente TEXT NOT NULL,
            mensagem TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS grupos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            criador TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS grupo_membros (
            grupo_id INTEGER NOT NULL,
            username TEXT NOT NULL
        )
    ''')
    conexao.commit()
    conexao.close()
    print("[SISTEMA] Base de dados verificada.")


def enviar_pacote_seguro(conn, pacote: dict):
    """Encapsula e cifra qualquer pacote antes do envio pelo socket."""
    sessao = sessoes_clientes.get(conn)
    if sessao:
        dados_envio = sessao.cifrar_envelope(pacote)
    else:
        dados_envio = pacote
    payload = (json.dumps(dados_envio) + "\n").encode('utf-8')
    try:
        conn.sendall(payload)
    except Exception:
        pass


def realizar_handshake_servidor(conn) -> bool:
    """Executa o acordo de chaves inicial DHE + HKDF com o cliente."""
    try:
        # 1. Envia parâmetros públicos (p, g)
        conn.sendall((json.dumps({
            "action": "dh_params",
            "p": hex(NUMEROS_DH.p),
            "g": NUMEROS_DH.g
        }) + "\n").encode('utf-8'))

        # 2. Recebe a chave pública do cliente e o salt
        linha = ""
        while "\n" not in linha:
            linha += conn.recv(4096).decode('utf-8')
        dados = json.loads(linha.strip())

        if dados.get("action") != "dh_exchange":
            return False

        y_cliente = int(dados["public_key"], 16)
        salt_cliente = bytes.fromhex(dados["salt"])

        # 3. Gera par efêmero do servidor e calcula segredo
        chave_pub_cliente = dh.DHPublicNumbers(y_cliente, NUMEROS_DH).public_key()
        priv_servidor = PARAMETROS_DH.generate_private_key()
        pub_servidor = priv_servidor.public_key()
        segredo = priv_servidor.exchange(chave_pub_cliente)

        chave_aes, chave_hmac = derivar_chaves(segredo, salt_cliente)
        limite_msg = secrets.SystemRandom().randint(*INTERVALO_MENSAGENS)
        session_id = secrets.token_hex(16)

        sessao = SessaoCripto(session_id, chave_aes, chave_hmac, limite_msg)
        sessoes_clientes[conn] = sessao

        # 4. Envia resposta com chave pública e limites
        y_servidor = pub_servidor.public_numbers().y
        conn.sendall((json.dumps({
            "action": "dh_response",
            "public_key": hex(y_servidor),
            "session_id": session_id,
            "limit_messages": limite_msg
        }) + "\n").encode('utf-8'))

        print(f"[SEGURANÇA] Handshake DHE concluído com sucesso. Sessão: {session_id[:8]}... (Limite: {limite_msg} msgs)")
        return True
    except Exception as e:
        print(f"[ERRO HANDSHAKE] Falha no aperto de mão: {e}")
        return False


def enviar_lista_contatos():
    try:
        conexao = sqlite3.connect('chat_uabj.db')
        cursor = conexao.cursor()
        cursor.execute("SELECT username FROM usuarios")
        todos_usuarios = [row[0] for row in cursor.fetchall()]

        for username, conn in list(clientes_online.items()):
            lista_formatada = []
            for user in todos_usuarios:
                status = "online" if user in clientes_online else "offline"
                lista_formatada.append({"username": user, "status": status})

            cursor.execute("SELECT g.nome, g.criador FROM grupos g JOIN grupo_membros gm ON g.id = gm.grupo_id WHERE gm.username = ?", (username,))
            meus_grupos = [{"nome": row[0], "criador": row[1]} for row in cursor.fetchall()]

            pacote = {
                "action": "update_contacts",
                "contacts": lista_formatada,
                "groups": meus_grupos
            }
            enviar_pacote_seguro(conn, pacote)
        conexao.close()
    except Exception as e:
        print(f"[ERRO] Falha ao atualizar contactos: {e}")


def processar_autenticacao(conn, dados_json):
    acao = dados_json.get("action")
    username = dados_json.get("username")
    password = dados_json.get("password")

    conexao = sqlite3.connect('chat_uabj.db')
    cursor = conexao.cursor()
    resposta = {}
    usuario_logado = None

    if acao == "register":
        try:
            cursor.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)", (username, password))
            conexao.commit()
            resposta = {"action": "register_response", "status": "success"}
            print(f"[REGISTO] Novo utilizador: {username}")
        except sqlite3.IntegrityError:
            resposta = {"action": "register_response", "status": "error", "message": "Utilizador já existe."}

    elif acao == "login":
        cursor.execute("SELECT id FROM usuarios WHERE username = ? AND password = ?", (username, password))
        if cursor.fetchone():
            resposta = {"action": "login_response", "status": "success"}
            usuario_logado = username
            clientes_online[username] = conn
            print(f"[LOGIN] {username} autenticado com canal seguro.")
        else:
            resposta = {"action": "login_response", "status": "error", "message": "Credenciais incorretas."}

    enviar_pacote_seguro(conn, resposta)

    if usuario_logado:
        time.sleep(0.1)
        enviar_lista_contatos()

        cursor.execute("SELECT id, remetente, mensagem FROM mensagens_offline WHERE destinatario = ?", (usuario_logado,))
        msgs_pendentes = cursor.fetchall()

        for m_id, rem, cont in msgs_pendentes:
            is_group = False
            receiver = usuario_logado
            sender = rem
            if rem.startswith("GRP:"):
                partes = rem.split(":")
                is_group = True
                receiver = partes[1]
                sender = partes[2]

            pacote_entrega = {
                "action": "receive_message",
                "sender": sender,
                "receiver": receiver,
                "content": cont,
                "is_group": is_group
            }
            enviar_pacote_seguro(conn, pacote_entrega)

        cursor.execute("DELETE FROM mensagens_offline WHERE destinatario = ?", (usuario_logado,))
        conexao.commit()

    conexao.close()
    return usuario_logado


def lidar_com_cliente(conn, addr):
    print(f"[CONEXÃO] Ligação recebida de {addr}. A iniciar handshake criptográfico...")
    if not realizar_handshake_servidor(conn):
        conn.close()
        return

    usuario_atual = None
    buffer = ""

    try:
        while True:
            chunk = conn.recv(8192).decode('utf-8')
            if not chunk:
                break
            buffer += chunk

            while "\n" in buffer:
                linha, buffer = buffer.split("\n", 1)
                linha = linha.strip()
                if not linha:
                    continue

                dados_brutos = json.loads(linha)

                # Tratamento de renovação de chaves (Rekeying)
                if dados_brutos.get("action") == "dh_rekey":
                    y_c = int(dados_brutos["public_key"], 16)
                    salt_c = bytes.fromhex(dados_brutos["salt"])
                    priv_srv = PARAMETROS_DH.generate_private_key()
                    segredo = priv_srv.exchange(dh.DHPublicNumbers(y_c, NUMEROS_DH).public_key())
                    k_aes, k_hmac = derivar_chaves(segredo, salt_c)
                    limite_msg = secrets.SystemRandom().randint(*INTERVALO_MENSAGENS)
                    nova_sessao = secrets.token_hex(16)
                    sessoes_clientes[conn] = SessaoCripto(nova_sessao, k_aes, k_hmac, limite_msg)

                    conn.sendall((json.dumps({
                        "action": "dh_rekey_response",
                        "public_key": hex(priv_srv.public_key().public_numbers().y),
                        "session_id": nova_sessao,
                        "limit_messages": limite_msg
                    }) + "\n").encode('utf-8'))
                    print(f"[SEGURANÇA] Sessão renovada para {usuario_atual or addr}. Novo limite: {limite_msg}")
                    continue

                # Processamento exclusivo de envelopes protegidos
                sessao = sessoes_clientes.get(conn)
                if dados_brutos.get("action") == "secure_envelope":
                    try:
                        dados = sessao.decifrar_envelope(dados_brutos)
                    except ValueError:
                        print(f"[SEGURANÇA] Alerta: MAC inválido de {usuario_atual or addr}! Pacote descartado.")
                        continue
                else:
                    dados = dados_brutos

                acao_atual = dados.get("action")

                if acao_atual in ["login", "register"]:
                    logado = processar_autenticacao(conn, dados)
                    if logado:
                        usuario_atual = logado

                elif acao_atual == "send_message":
                    remetente = dados.get("sender")
                    destinatario = dados.get("receiver")
                    conteudo = dados.get("content")
                    is_group = dados.get("is_group", False)

                    if is_group:
                        conexao = sqlite3.connect('chat_uabj.db')
                        cursor = conexao.cursor()
                        cursor.execute("SELECT username FROM grupo_membros WHERE grupo_id = (SELECT id FROM grupos WHERE nome = ?)", (destinatario,))
                        membros = [row[0] for row in cursor.fetchall()]

                        for membro in membros:
                            if membro != remetente:
                                if membro in clientes_online:
                                    conn_dest = clientes_online[membro]
                                    enviar_pacote_seguro(conn_dest, {
                                        "action": "receive_message",
                                        "sender": remetente,
                                        "receiver": destinatario,
                                        "content": conteudo,
                                        "is_group": True
                                    })
                                else:
                                    rem_fmt = f"GRP:{destinatario}:{remetente}"
                                    cursor.execute("INSERT INTO mensagens_offline (remetente, destinatario, mensagem) VALUES (?, ?, ?)",
                                                   (rem_fmt, membro, conteudo))
                        conexao.commit()
                        conexao.close()
                    else:
                        if destinatario in clientes_online:
                            conn_dest = clientes_online[destinatario]
                            enviar_pacote_seguro(conn_dest, {
                                "action": "receive_message",
                                "sender": remetente,
                                "receiver": destinatario,
                                "content": conteudo,
                                "is_group": False
                            })
                        else:
                            conexao = sqlite3.connect('chat_uabj.db')
                            cursor = conexao.cursor()
                            cursor.execute("INSERT INTO mensagens_offline (remetente, destinatario, mensagem) VALUES (?, ?, ?)",
                                           (remetente, destinatario, conteudo))
                            conexao.commit()
                            conexao.close()

                elif acao_atual in ["typing_start", "typing_stop"]:
                    remetente = dados.get("sender")
                    destinatario = dados.get("receiver")
                    is_group = dados.get("is_group", False)

                    if is_group:
                        conexao = sqlite3.connect('chat_uabj.db')
                        cursor = conexao.cursor()
                        cursor.execute("SELECT username FROM grupo_membros WHERE grupo_id = (SELECT id FROM grupos WHERE nome = ?)", (destinatario,))
                        membros = [row[0] for row in cursor.fetchall()]
                        conexao.close()
                        for m in membros:
                            if m != remetente and m in clientes_online:
                                enviar_pacote_seguro(clientes_online[m], dados)
                    else:
                        if destinatario in clientes_online:
                            enviar_pacote_seguro(clientes_online[destinatario], dados)

                elif acao_atual == "create_group":
                    nome_grupo = dados.get("group_name")
                    membros = dados.get("members", [])
                    if usuario_atual not in membros:
                        membros.append(usuario_atual)
                    membros = list(set(membros))

                    conexao = sqlite3.connect('chat_uabj.db')
                    cursor = conexao.cursor()
                    try:
                        cursor.execute("INSERT INTO grupos (nome, criador) VALUES (?, ?)", (nome_grupo, usuario_atual))
                        grupo_id = cursor.lastrowid
                        for m_user in membros:
                            cursor.execute("INSERT INTO grupo_membros (grupo_id, username) VALUES (?, ?)", (grupo_id, m_user))
                        conexao.commit()
                    except Exception:
                        pass
                    finally:
                        conexao.close()
                    enviar_lista_contatos()

                elif acao_atual == "delete_group":
                    nome_grupo = dados.get("group_name")
                    conexao = sqlite3.connect('chat_uabj.db')
                    cursor = conexao.cursor()
                    try:
                        cursor.execute("SELECT id, criador FROM grupos WHERE nome = ?", (nome_grupo,))
                        res = cursor.fetchone()
                        if res and res[1] == usuario_atual:
                            cursor.execute("DELETE FROM grupo_membros WHERE grupo_id = ?", (res[0],))
                            cursor.execute("DELETE FROM grupos WHERE id = ?", (res[0],))
                            conexao.commit()
                    finally:
                        conexao.close()
                    enviar_lista_contatos()

                elif acao_atual == "add_group_members":
                    nome_g = dados.get("group_name")
                    novos = dados.get("members", [])
                    conexao = sqlite3.connect('chat_uabj.db')
                    cursor = conexao.cursor()
                    try:
                        cursor.execute("SELECT id FROM grupos WHERE nome = ?", (nome_g,))
                        res = cursor.fetchone()
                        if res:
                            g_id = res[0]
                            for n in novos:
                                cursor.execute("INSERT OR IGNORE INTO grupo_membros (grupo_id, username) VALUES (?, ?)", (g_id, n))
                            conexao.commit()
                    finally:
                        conexao.close()
                    enviar_lista_contatos()

                elif acao_atual == "remove_group_members":
                    nome_g = dados.get("group_name")
                    remover = dados.get("members", [])
                    conexao = sqlite3.connect('chat_uabj.db')
                    cursor = conexao.cursor()
                    try:
                        cursor.execute("SELECT id FROM grupos WHERE nome = ?", (nome_g,))
                        res = cursor.fetchone()
                        if res:
                            g_id = res[0]
                            for r in remover:
                                cursor.execute("DELETE FROM grupo_membros WHERE grupo_id = ? AND username = ?", (g_id, r))
                            conexao.commit()
                    finally:
                        conexao.close()
                    enviar_lista_contatos()

    except Exception:
        pass
    finally:
        if usuario_atual and usuario_atual in clientes_online:
            del clientes_online[usuario_atual]
            print(f"[DESCONEXÃO] {usuario_atual} desconectou-se.")
            enviar_lista_contatos()
        if conn in sessoes_clientes:
            del sessoes_clientes[conn]
        conn.close()


def iniciar_servidor():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((HOST, PORT))
    servidor.listen()
    print(f"[ONLINE] Servidor de Chat Seguro ativo na porta {PORT}...")

    while True:
        conn, addr = servidor.accept()
        threading.Thread(target=lidar_com_cliente, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    inicializar_banco()
    iniciar_servidor()