import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import json
import sqlite3
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import dh

from chat_cripto import (
    derivar_chaves,
    SessaoCripto,
)

HOST = '127.0.0.1'
PORT = 5050


class ChatCliente:
    def __init__(self, master):
        self.master = master
        self.master.title("UABJ Chat - Seguro")
        self.master.geometry("850x600")
        self.master.minsize(700, 500)
        
        self.socket_cliente = None
        self.conectado = False
        self.sessao: SessaoCripto = None
        self.parametros_dh = None
        self.rekey_em_andamento = False
        self.priv_rekey_temp = None
        self.salt_rekey_temp = None
        
        self.usuario_atual = ""
        self.destinatario_atual = None
        self.is_group_atual = False
        self.is_admin_atual = False
        self.db_local = ""
        self.contatos_status = []
        self.meus_grupos = []
        self.mensagens_nao_lidas = {}
        self.timer_digitacao = None
        self.tema_escuro = True
        self.ultimo_remetente = None
        self.painel_emoji_aberto = False

        self.c = {
            "dark": {"bg_main": "#313338", "bg_panel": "#2B2D31", "bg_header": "#1E1F22", "fg_text": "#DBDEE1", "fg_muted": "#8696a0", "inp_bg": "#383A40", "inp_fg": "#DBDEE1", "cursor": "white", "btn_bg": "#00a884", "tag_voce": "#00a884", "tag_outro": "#5865F2", "sel_bg": "#404249", "hora_fg": "#8696a0", "emoji_bg": "#2B2D31"},
            "light": {"bg_main": "#ffffff", "bg_panel": "#f0f2f5", "bg_header": "#efeae2", "fg_text": "#111b21", "fg_muted": "#54656f", "inp_bg": "#f0f2f5", "inp_fg": "#111b21", "cursor": "black", "btn_bg": "#00a884", "tag_voce": "#005c4b", "tag_outro": "#2B2D31", "sel_bg": "#e9edef", "hora_fg": "#667781", "emoji_bg": "#f0f2f5"}
        }
        
        self.frame_login = tk.Frame(self.master)
        self.frame_login.pack(expand=True)
        
        self.lbl_user = tk.Label(self.frame_login, text="Nome de Utilizador:", font=("Segoe UI", 11))
        self.lbl_user.pack()
        self.entry_username = tk.Entry(self.frame_login, font=("Segoe UI", 11), relief=tk.FLAT)
        self.entry_username.pack(pady=5, ipady=4)
        
        self.lbl_pass = tk.Label(self.frame_login, text="Palavra-passe:", font=("Segoe UI", 11))
        self.lbl_pass.pack()
        self.entry_password = tk.Entry(self.frame_login, show="*", font=("Segoe UI", 11), relief=tk.FLAT)
        self.entry_password.pack(pady=5, ipady=4)
        
        self.frame_botoes = tk.Frame(self.frame_login)
        self.frame_botoes.pack(pady=20)
        self.btn_login = tk.Button(self.frame_botoes, text="Login", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, width=12, command=lambda: self.enviar_credenciais("login"))
        self.btn_login.pack(side=tk.LEFT, padx=5, ipady=4)
        self.btn_registrar = tk.Button(self.frame_botoes, text="Registar", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, width=12, command=lambda: self.enviar_credenciais("register"))
        self.btn_registrar.pack(side=tk.LEFT, padx=5, ipady=4)

        self.frame_chat = tk.Frame(self.master)
        
        self.frame_direita = tk.Frame(self.frame_chat, width=280)
        self.frame_direita.pack(side=tk.RIGHT, fill=tk.Y)
        self.frame_direita.pack_propagate(False)

        self.frame_esquerda = tk.Frame(self.frame_chat)
        self.frame_esquerda.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        self.frame_header = tk.Frame(self.frame_esquerda, height=65)
        self.frame_header.pack(fill=tk.X, side=tk.TOP)
        self.frame_header.pack_propagate(False)

        self.label_chat_com = tk.Label(self.frame_header, text="Selecione um contacto", font=("Segoe UI", 13, "bold"))
        self.label_chat_com.pack(side=tk.LEFT, padx=20, pady=15)

        self.btn_fechar_chat = tk.Button(self.frame_header, text="✕", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, command=self.fechar_conversa)
        self.btn_sair_grupo = tk.Button(self.frame_header, text="🚪 Sair", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, command=self.sair_do_grupo)
        self.btn_add_membro = tk.Button(self.frame_header, text="➕ Adicionar", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, command=self.abrir_tela_add_membro)
        self.btn_remover_membro = tk.Button(self.frame_header, text="➖ Remover", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, command=self.abrir_tela_remover_membro)
        self.btn_excluir_grupo = tk.Button(self.frame_header, text="🗑️ Excluir", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, command=self.excluir_grupo)

        self.frame_bottom_area = tk.Frame(self.frame_esquerda)
        self.frame_bottom_area.pack(side=tk.BOTTOM, fill=tk.X)

        self.frame_input = tk.Frame(self.frame_bottom_area, height=80, padx=20, pady=15)
        self.frame_input.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.btn_emoji = tk.Button(self.frame_input, text="😀", font=("Segoe UI Emoji", 15), relief=tk.FLAT, bd=0, cursor="hand2", command=self.alternar_painel_emoji)
        self.btn_emoji.pack(side=tk.LEFT, padx=(0, 10))
        
        self.entry_mensagem = tk.Entry(self.frame_input, font=("Segoe UI", 12), relief=tk.FLAT)
        self.entry_mensagem.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=(0, 10), ipady=8)
        self.entry_mensagem.bind("<Return>", self.enviar_mensagem)
        self.entry_mensagem.bind("<KeyRelease>", self.tecla_pressionada)
        
        self.btn_enviar = tk.Button(self.frame_input, text="Enviar", font=("Segoe UI", 11, "bold"), relief=tk.FLAT, bd=0, width=10, command=self.enviar_mensagem, state=tk.DISABLED)
        self.btn_enviar.pack(side=tk.RIGHT, fill=tk.Y)
        self.entry_mensagem.config(state=tk.DISABLED)

        self.label_digitando = tk.Label(self.frame_bottom_area, text="", font=("Segoe UI", 9, "italic"))
        self.label_digitando.pack(side=tk.BOTTOM, anchor="w", padx=25)

        self.frame_emojis = tk.Frame(self.frame_bottom_area, bd=0)
        self.emojis_lista = ['😀', '😂', '😍', '🥰', '😎', '🤔', '😢', '😡', '👍', '🙏', '👏', '🎉', '❤️', '🔥', '💯', '💀', '👀', '🤡']
        self.botoes_emoji = []
        for i, emj in enumerate(self.emojis_lista):
            btn = tk.Button(self.frame_emojis, text=emj, font=("Segoe UI Emoji", 14), relief=tk.FLAT, bd=0, cursor="hand2", command=lambda e=emj: self.inserir_emoji(e))
            btn.grid(row=i//6, column=i%6, padx=2, pady=2)
            self.botoes_emoji.append(btn)

        self.area_mensagens = scrolledtext.ScrolledText(self.frame_esquerda, state='disabled', font=("Segoe UI", 12), wrap=tk.WORD, bd=0, highlightthickness=0, padx=30, pady=10)
        self.area_mensagens.pack(expand=True, fill=tk.BOTH, side=tk.TOP)

        self.frame_perfil = tk.Frame(self.frame_direita, height=65)
        self.frame_perfil.pack(fill=tk.X, side=tk.TOP)
        self.frame_perfil.pack_propagate(False)
        
        self.label_meu_usuario = tk.Label(self.frame_perfil, text="", font=("Segoe UI", 12, "bold"))
        self.label_meu_usuario.pack(side=tk.LEFT, padx=20, pady=15)

        self.btn_tema = tk.Button(self.frame_perfil, text="🌓", font=("Segoe UI", 15), relief=tk.FLAT, bd=0, command=self.alternar_tema, cursor="hand2")
        self.btn_tema.pack(side=tk.RIGHT, padx=5)
        
        self.btn_novo_grupo = tk.Button(self.frame_perfil, text="👥+", font=("Segoe UI", 12), relief=tk.FLAT, bd=0, command=self.abrir_tela_novo_grupo, cursor="hand2")
        self.btn_novo_grupo.pack(side=tk.RIGHT, padx=5)

        self.lista_contatos = tk.Listbox(self.frame_direita, font=("Segoe UI", 12, "bold"), relief=tk.FLAT, highlightthickness=0, bd=0)
        self.lista_contatos.pack(expand=True, fill=tk.BOTH, padx=10, pady=10, side=tk.TOP)
        self.lista_contatos.bind("<<ListboxSelect>>", self.selecionar_contato)

        self.aplicar_tema()

    # --- CAMADA CRIPTOGRÁFICA ---

    def realizar_handshake_cliente(self) -> bool:
        try:
            linha = ""
            while "\n" not in linha:
                linha += self.socket_cliente.recv(4096).decode('utf-8')
            dados_p = json.loads(linha.strip())

            p = int(dados_p["p"], 16)
            g = dados_p["g"]
            self.parametros_dh = dh.DHParameterNumbers(p, g).parameters()

            priv_cliente = self.parametros_dh.generate_private_key()
            pub_cliente = priv_cliente.public_key().public_numbers().y
            salt_cliente = os.urandom(16)

            self.socket_cliente.sendall((json.dumps({
                "action": "dh_exchange",
                "public_key": hex(pub_cliente),
                "salt": salt_cliente.hex()
            }) + "\n").encode('utf-8'))

            linha_resp = ""
            while "\n" not in linha_resp:
                linha_resp += self.socket_cliente.recv(4096).decode('utf-8')
            dados_resp = json.loads(linha_resp.strip())

            y_srv = int(dados_resp["public_key"], 16)
            sess_id = dados_resp["session_id"]
            limite_msg = dados_resp["limit_messages"]

            pub_srv = dh.DHPublicNumbers(y_srv, dh.DHParameterNumbers(p, g)).public_key()
            segredo = priv_cliente.exchange(pub_srv)
            k_aes, k_hmac = derivar_chaves(segredo, salt_cliente)

            self.sessao = SessaoCripto(sess_id, k_aes, k_hmac, limite_msg)
            print(f"[SEGURANÇA] Handshake inicial OK ({sess_id[:8]}...). Limite: {limite_msg} msgs.")
            return True
        except Exception as e:
            print(f"[ERRO HANDSHAKE] {e}")
            return False

    def renovar_sessao_se_necessario(self):
        if not self.sessao or not self.sessao.precisa_renovar():
            return
        if self.rekey_em_andamento:
            return

        print(f"[SEGURANÇA] Limite atingido ({self.sessao.contador_mensagens}/{self.sessao.limite_mensagens})! Renovando chaves...")
        try:
            self.rekey_em_andamento = True
            self.priv_rekey_temp = self.parametros_dh.generate_private_key()
            pub_c = self.priv_rekey_temp.public_key().public_numbers().y
            self.salt_rekey_temp = os.urandom(16)

            self.socket_cliente.sendall((json.dumps({
                "action": "dh_rekey",
                "public_key": hex(pub_c),
                "salt": self.salt_rekey_temp.hex()
            }) + "\n").encode('utf-8'))
        except Exception as e:
            self.rekey_em_andamento = False
            print(f"[ERRO RENOVAÇÃO] {e}")

    def enviar_pacote(self, pacote: dict):
        self.renovar_sessao_se_necessario()
        envelope = self.sessao.cifrar_envelope(pacote)
        self.socket_cliente.sendall((json.dumps(envelope) + "\n").encode('utf-8'))

    # --- COMUNICAÇÃO E INTERFACE ---

    def conectar_servidor_se_necessario(self):
        if not self.conectado:
            try:
                self.socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket_cliente.connect((HOST, PORT))
                
                if not self.realizar_handshake_cliente():
                    messagebox.showerror("Erro Criptográfico", "Falha no acordo de chaves.")
                    return False

                self.conectado = True
                threading.Thread(target=self.escutar_servidor, daemon=True).start()
                return True
            except Exception:
                messagebox.showerror("Erro", "Servidor offline.")
                return False
        return True

    def enviar_credenciais(self, acao):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if not username or not password:
            messagebox.showwarning("Erro", "Preencha o utilizador e a palavra-passe!")
            return

        if self.conectar_servidor_se_necessario():
            self.usuario_atual = username
            self.enviar_pacote({"action": acao, "username": username, "password": password})

    def escutar_servidor(self):
        buffer = ""
        while True:
            try:
                chunk = self.socket_cliente.recv(8192).decode('utf-8')
                if not chunk:
                    break
                buffer += chunk

                while "\n" in buffer:
                    linha, buffer = buffer.split("\n", 1)
                    linha = linha.strip()
                    if not linha:
                        continue

                    dados_brutos = json.loads(linha)

                    if dados_brutos.get("action") == "dh_rekey_response":
                        y_srv = int(dados_brutos["public_key"], 16)
                        limite = dados_brutos["limit_messages"]
                        sess_id = dados_brutos["session_id"]
                        num_p = self.parametros_dh.parameter_numbers()
                        pub_srv = dh.DHPublicNumbers(y_srv, num_p).public_key()
                        segredo = self.priv_rekey_temp.exchange(pub_srv)
                        k_aes, k_hmac = derivar_chaves(segredo, self.salt_rekey_temp)
                        self.sessao = SessaoCripto(sess_id, k_aes, k_hmac, limite)
                        self.rekey_em_andamento = False
                        print(f"[SEGURANÇA] Sessão renovada! Nova sessão: {sess_id[:8]}... (Limite: {limite} msgs)")
                        continue

                    if dados_brutos.get("action") == "secure_envelope":
                        try:
                            dados = self.sessao.decifrar_envelope(dados_brutos)
                        except ValueError:
                            print("[SEGURANÇA] Alerta: MAC inválido recebido! Pacote descartado.")
                            continue
                    else:
                        dados = dados_brutos

                    acao = dados.get("action")

                    if acao == "register_response":
                        if dados.get("status") == "error":
                            messagebox.showwarning("Aviso", dados.get("message"))
                        else:
                            messagebox.showinfo("Sucesso", "Registo concluído! Clique em Login.")

                    elif acao == "login_response":
                        if dados.get("status") == "success":
                            self.inicializar_banco_local(self.usuario_atual)
                            self.label_meu_usuario.config(text=f"👤 {self.usuario_atual}")
                            self.frame_login.pack_forget()
                            self.frame_chat.pack(expand=True, fill=tk.BOTH)
                            self.master.title(f"UABJ Chat - {self.usuario_atual} [Seguro]")
                        else:
                            messagebox.showwarning("Aviso", dados.get("message"))

                    elif acao == "update_contacts":
                        self.contatos_status = dados.get("contacts", [])
                        self.meus_grupos = dados.get("groups", [])
                        if self.is_group_atual:
                            if not any(g["nome"] == self.destinatario_atual for g in self.meus_grupos):
                                self.fechar_conversa()
                        self.renderizar_lista_contatos()

                    elif acao == "receive_message":
                        remetente = dados.get("sender")
                        conteudo = dados.get("content")
                        is_group = dados.get("is_group", False)
                        receiver = dados.get("receiver")

                        contato_alvo = receiver if is_group else remetente
                        remetente_real = remetente if is_group else ""

                        self.salvar_mensagem_local(contato_alvo, 'recebida', conteudo, remetente_real)

                        if contato_alvo == self.destinatario_atual:
                            hora_atual = datetime.now().strftime("%H:%M")
                            self._inserir_na_tela(remetente_real if is_group else remetente, conteudo, hora_atual, False)
                        else:
                            self.mensagens_nao_lidas[contato_alvo] = self.mensagens_nao_lidas.get(contato_alvo, 0) + 1
                            self.renderizar_lista_contatos()

                    elif acao in ["typing_start", "typing_stop"]:
                        sender = dados.get("sender")
                        receiver = dados.get("receiver")
                        is_group = dados.get("is_group", False)
                        txt = f"{sender} está a escrever..." if acao == "typing_start" else ""

                        if is_group and receiver == self.destinatario_atual and self.is_group_atual:
                            self.label_digitando.config(text=txt)
                        elif not is_group and sender == self.destinatario_atual and not self.is_group_atual:
                            self.label_digitando.config(text=txt)

            except Exception as e:
                print(f"[CONEXÃO] Ligação terminada: {e}")
                self.conectado = False
                break

    def enviar_mensagem(self, event=None):
        if not self.destinatario_atual:
            return
        mensagem = self.entry_mensagem.get().strip()
        if mensagem and self.conectado:
            pacote = {
                "action": "send_message",
                "sender": self.usuario_atual,
                "receiver": self.destinatario_atual,
                "content": mensagem,
                "is_group": self.is_group_atual
            }
            self.enviar_pacote(pacote)
            self.salvar_mensagem_local(self.destinatario_atual, 'enviada', mensagem, "Você")
            hora_atual = datetime.now().strftime("%H:%M")
            self._inserir_na_tela("Você", mensagem, hora_atual, True)
            self.entry_mensagem.delete(0, tk.END)

            if self.timer_digitacao is not None:
                self.master.after_cancel(self.timer_digitacao)
                self.parar_digitacao()
            if self.painel_emoji_aberto:
                self.alternar_painel_emoji()

    def enviar_evento_digitacao(self, acao):
        if self.conectado and self.destinatario_atual:
            self.enviar_pacote({
                "action": acao,
                "sender": self.usuario_atual,
                "receiver": self.destinatario_atual,
                "is_group": self.is_group_atual
            })

    def tecla_pressionada(self, event):
        if event.keysym == 'Return' or not self.destinatario_atual:
            return
        if self.timer_digitacao is not None:
            self.master.after_cancel(self.timer_digitacao)
        else:
            self.enviar_evento_digitacao("typing_start")
        self.timer_digitacao = self.master.after(2000, self.parar_digitacao)

    def parar_digitacao(self):
        self.enviar_evento_digitacao("typing_stop")
        self.timer_digitacao = None

    def inserir_emoji(self, emoji):
        self.entry_mensagem.insert(tk.END, emoji)
        self.entry_mensagem.focus()

    def alternar_painel_emoji(self):
        if self.painel_emoji_aberto:
            self.frame_emojis.pack_forget()
            self.painel_emoji_aberto = False
            t = self.c["dark"] if self.tema_escuro else self.c["light"]
            self.btn_emoji.config(fg=t["fg_muted"])
        else:
            self.frame_emojis.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 5))
            self.painel_emoji_aberto = True
            self.btn_emoji.config(fg="#00a884")

    def _centralizar_janela(self, win, width, height):
        win.update_idletasks()
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (width // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (height // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")

    def abrir_tela_novo_grupo(self):
        win = tk.Toplevel(self.master)
        win.title("Criar Sala")
        self._centralizar_janela(win, 400, 500)
        t = self.c["dark"] if self.tema_escuro else self.c["light"]
        win.configure(bg=t["bg_main"])

        tk.Label(win, text="1. Nome do Grupo:", bg=t["bg_main"], fg=t["fg_text"], font=("Segoe UI", 11, "bold")).pack(pady=(15, 5))
        entry_nome = tk.Entry(win, font=("Segoe UI", 11), bg=t["inp_bg"], fg=t["inp_fg"], relief=tk.FLAT, insertbackground=t["cursor"])
        entry_nome.pack(pady=5, padx=20, fill=tk.X, ipady=4)

        tk.Label(win, text="2. Selecione os membros:", bg=t["bg_main"], fg=t["fg_text"], font=("Segoe UI", 10, "bold")).pack(pady=(15, 5))
        frame_lista = tk.Frame(win, bg=t["bg_panel"])
        frame_lista.pack(expand=True, fill=tk.BOTH, padx=20, pady=5)
        lista_membros = tk.Listbox(frame_lista, selectmode=tk.MULTIPLE, font=("Segoe UI", 11), bg=t["bg_panel"], fg=t["fg_text"], relief=tk.FLAT, highlightthickness=0, selectbackground=t["sel_bg"])
        lista_membros.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        for contato in self.contatos_status:
            if contato["username"] != self.usuario_atual:
                lista_membros.insert(tk.END, f"  {contato['username']}")

        def confirmar():
            nome_grupo = entry_nome.get().strip()
            selecionados = lista_membros.curselection()
            if not nome_grupo or len(selecionados) == 0:
                messagebox.showwarning("Aviso", "Preencha o nome e selecione os membros.")
                return
            membros_nomes = [lista_membros.get(i).strip() for i in selecionados]
            self.enviar_pacote({"action": "create_group", "group_name": nome_grupo, "members": membros_nomes})
            win.destroy()

        tk.Button(win, text="Criar Grupo", bg=t["btn_bg"], fg="white", font=("Segoe UI", 11, "bold"), relief=tk.FLAT, command=confirmar).pack(pady=20, ipady=5, ipadx=10)

    def abrir_tela_add_membro(self):
        if not self.is_group_atual or not self.destinatario_atual: return
        win = tk.Toplevel(self.master)
        win.title(f"Adicionar a {self.destinatario_atual}")
        self._centralizar_janela(win, 350, 450)
        t = self.c["dark"] if self.tema_escuro else self.c["light"]
        win.configure(bg=t["bg_main"])
        frame_lista = tk.Frame(win, bg=t["bg_panel"])
        frame_lista.pack(expand=True, fill=tk.BOTH, padx=20, pady=5)
        lista_membros = tk.Listbox(frame_lista, selectmode=tk.MULTIPLE, font=("Segoe UI", 11), bg=t["bg_panel"], fg=t["fg_text"], relief=tk.FLAT, highlightthickness=0, selectbackground=t["sel_bg"])
        lista_membros.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        for contato in self.contatos_status:
            if contato["username"] != self.usuario_atual:
                lista_membros.insert(tk.END, f"  {contato['username']}")

        def confirmar():
            selecionados = lista_membros.curselection()
            if len(selecionados) == 0: return
            nomes = [lista_membros.get(i).strip() for i in selecionados]
            self.enviar_pacote({"action": "add_group_members", "group_name": self.destinatario_atual, "members": nomes})
            win.destroy()

        tk.Button(win, text="Adicionar", bg=t["btn_bg"], fg="white", font=("Segoe UI", 11, "bold"), relief=tk.FLAT, command=confirmar).pack(pady=20, ipady=5, ipadx=10)

    def abrir_tela_remover_membro(self):
        if not self.is_group_atual or not self.destinatario_atual: return
        win = tk.Toplevel(self.master)
        win.title(f"Remover de {self.destinatario_atual}")
        self._centralizar_janela(win, 350, 450)
        t = self.c["dark"] if self.tema_escuro else self.c["light"]
        win.configure(bg=t["bg_main"])
        frame_lista = tk.Frame(win, bg=t["bg_panel"])
        frame_lista.pack(expand=True, fill=tk.BOTH, padx=20, pady=5)
        lista_membros = tk.Listbox(frame_lista, selectmode=tk.MULTIPLE, font=("Segoe UI", 11), bg=t["bg_panel"], fg=t["fg_text"], relief=tk.FLAT, highlightthickness=0, selectbackground=t["sel_bg"])
        lista_membros.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        for g in self.meus_grupos:
            if g["nome"] == self.destinatario_atual:
                for m in g.get("membros", []):
                    lista_membros.insert(tk.END, f"  {m}")

        def confirmar():
            selecionados = lista_membros.curselection()
            if len(selecionados) == 0: return
            nomes = [lista_membros.get(i).strip() for i in selecionados]
            self.enviar_pacote({"action": "remove_group_members", "group_name": self.destinatario_atual, "members": nomes})
            win.destroy()

        tk.Button(win, text="Remover Membro", bg="#DA373C", fg="white", font=("Segoe UI", 11, "bold"), relief=tk.FLAT, command=confirmar).pack(pady=20, ipady=5, ipadx=10)

    def excluir_grupo(self):
        if not self.is_group_atual or not self.destinatario_atual: return
        if messagebox.askyesno("Excluir", f"Apagar o grupo '{self.destinatario_atual}' permanentemente?"):
            self.enviar_pacote({"action": "delete_group", "group_name": self.destinatario_atual})
            self.fechar_conversa()

    def sair_do_grupo(self):
        if not self.is_group_atual or not self.destinatario_atual: return
        if messagebox.askyesno("Sair", f"Sair do grupo '{self.destinatario_atual}'?"):
            self.enviar_pacote({"action": "remove_group_members", "group_name": self.destinatario_atual, "members": [self.usuario_atual]})
            self.fechar_conversa()

    def alternar_tema(self):
        self.tema_escuro = not self.tema_escuro
        self.aplicar_tema()

    def aplicar_tema(self):
        t = self.c["dark"] if self.tema_escuro else self.c["light"]
        self.master.configure(bg=t["bg_main"])
        self.frame_login.configure(bg=t["bg_main"])
        self.frame_botoes.configure(bg=t["bg_main"])
        self.lbl_user.configure(bg=t["bg_main"], fg=t["fg_text"])
        self.lbl_pass.configure(bg=t["bg_main"], fg=t["fg_text"])
        self.entry_username.configure(bg=t["inp_bg"], fg=t["inp_fg"], insertbackground=t["cursor"])
        self.entry_password.configure(bg=t["inp_bg"], fg=t["inp_fg"], insertbackground=t["cursor"])
        self.btn_login.configure(bg=t["btn_bg"], fg="white")
        self.btn_registrar.configure(bg=t["btn_bg"], fg="white")

        self.frame_chat.configure(bg=t["bg_main"])
        self.frame_direita.configure(bg=t["bg_panel"])
        self.frame_esquerda.configure(bg=t["bg_main"])
        self.frame_bottom_area.configure(bg=t["bg_main"])
        self.frame_header.configure(bg=t["bg_panel"])
        self.label_chat_com.configure(bg=t["bg_panel"], fg=t["fg_text"])
        self.btn_fechar_chat.configure(bg=t["bg_main"], fg=t["fg_muted"])
        self.btn_sair_grupo.configure(bg=t["bg_main"], fg=t["fg_muted"])
        self.btn_add_membro.configure(bg=t["bg_main"], fg=t["fg_muted"])
        self.btn_remover_membro.configure(bg=t["bg_main"], fg=t["fg_muted"])
        self.btn_excluir_grupo.configure(bg=t["bg_main"], fg="#DA373C")

        self.frame_input.configure(bg=t["bg_header"])
        self.entry_mensagem.configure(bg=t["inp_bg"], fg=t["inp_fg"], insertbackground=t["cursor"])
        self.btn_enviar.configure(bg=t["btn_bg"], fg="white")
        self.btn_emoji.configure(bg=t["bg_header"], fg="#00a884" if self.painel_emoji_aberto else t["fg_muted"])
        self.frame_emojis.configure(bg=t["emoji_bg"])
        for btn in self.botoes_emoji:
            btn.configure(bg=t["emoji_bg"], fg=t["fg_text"], activebackground=t["sel_bg"], activeforeground=t["fg_text"])

        self.label_digitando.configure(bg=t["bg_main"], fg=t["fg_muted"])
        self.area_mensagens.configure(bg=t["bg_main"])
        self.frame_perfil.configure(bg=t["bg_header"])
        self.label_meu_usuario.configure(bg=t["bg_header"], fg=t["fg_text"])
        self.btn_tema.configure(bg=t["bg_header"], fg=t["fg_text"], activebackground=t["bg_header"], activeforeground=t["fg_text"])
        self.btn_novo_grupo.configure(bg=t["bg_header"], fg=t["fg_text"], activebackground=t["bg_header"], activeforeground=t["fg_text"])
        self.lista_contatos.configure(bg=t["bg_panel"], selectbackground=t["sel_bg"], selectforeground=t["fg_text"])

        self.area_mensagens.tag_configure('quebra_grupo', font=("Segoe UI", 6))
        self.area_mensagens.tag_configure('espaco_bolha', font=("Segoe UI", 4))
        self.area_mensagens.tag_configure('separador', foreground='#DA373C', justify='center', font=("Segoe UI", 9, "bold"))
        self.area_mensagens.tag_configure('nome_env', foreground=t["tag_voce"], justify='right', font=("Segoe UI", 10, "bold"), rmargin=20)
        self.area_mensagens.tag_configure('hora_env', foreground=t["hora_fg"], justify='right', font=("Segoe UI", 8), rmargin=20)
        self.area_mensagens.tag_configure('msg_env', foreground=t["fg_text"], justify='right', font=("Segoe UI", 12), rmargin=20)
        self.area_mensagens.tag_configure('nome_rec', foreground=t["tag_outro"], justify='left', font=("Segoe UI", 10, "bold"), lmargin1=20)
        self.area_mensagens.tag_configure('hora_rec', foreground=t["hora_fg"], justify='left', font=("Segoe UI", 8), lmargin1=20)
        self.area_mensagens.tag_configure('msg_rec', foreground=t["fg_text"], justify='left', font=("Segoe UI", 12), lmargin1=20, lmargin2=20, rmargin=100)
        self.renderizar_lista_contatos()

    def _inserir_na_tela(self, remetente, conteudo, hora, eh_enviada):
        self.area_mensagens.config(state='normal')
        hora_str = f"[{hora}]" if hora else ""
        if self.ultimo_remetente != remetente:
            self.area_mensagens.insert(tk.END, "\n", 'quebra_grupo')
            tag_n = 'nome_env' if eh_enviada else 'nome_rec'
            tag_h = 'hora_env' if eh_enviada else 'hora_rec'
            self.area_mensagens.insert(tk.END, f"{remetente} ", tag_n)
            self.area_mensagens.insert(tk.END, f"{hora_str}\n", tag_h)
        tag_msg = 'msg_env' if eh_enviada else 'msg_rec'
        self.area_mensagens.insert(tk.END, f"{conteudo}\n", tag_msg)
        self.area_mensagens.insert(tk.END, "\n", 'espaco_bolha')
        self.ultimo_remetente = remetente
        self.area_mensagens.yview(tk.END)
        self.area_mensagens.config(state='disabled')

    def fechar_conversa(self):
        self.destinatario_atual = None
        self.ultimo_remetente = None
        self.is_group_atual = False
        self.is_admin_atual = False
        self.label_chat_com.config(text="Selecione um contacto")
        self.btn_fechar_chat.pack_forget()
        self.btn_sair_grupo.pack_forget()
        self.btn_add_membro.pack_forget()
        self.btn_remover_membro.pack_forget()
        self.btn_excluir_grupo.pack_forget()
        self.btn_enviar.config(state=tk.DISABLED)
        self.entry_mensagem.delete(0, tk.END)
        self.entry_mensagem.config(state=tk.DISABLED)
        self.area_mensagens.config(state='normal')
        self.area_mensagens.delete('1.0', tk.END)
        self.area_mensagens.config(state='disabled')
        self.label_digitando.config(text="")
        if self.painel_emoji_aberto:
            self.alternar_painel_emoji()

    def inicializar_banco_local(self, username):
        self.db_local = f"historico_{username}.db"
        conexao = sqlite3.connect(self.db_local)
        cursor = conexao.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mensagens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contato TEXT,
                tipo TEXT,
                conteudo TEXT,
                timestamp TEXT,
                remetente_real TEXT
            )
        ''')
        conexao.commit()
        conexao.close()

    def salvar_mensagem_local(self, contato, tipo, conteudo, remetente_real=""):
        if not self.db_local: return
        conexao = sqlite3.connect(self.db_local)
        cursor = conexao.cursor()
        hora_atual = datetime.now().strftime("%H:%M")
        cursor.execute("INSERT INTO mensagens (contato, tipo, conteudo, timestamp, remetente_real) VALUES (?, ?, ?, ?, ?)",
                       (contato, tipo, conteudo, hora_atual, remetente_real))
        conexao.commit()
        conexao.close()

    def carregar_historico_na_tela(self, contato, nao_lidas):
        self.area_mensagens.config(state='normal')
        self.area_mensagens.delete('1.0', tk.END)
        self.ultimo_remetente = None
        if self.db_local and os.path.exists(self.db_local):
            conexao = sqlite3.connect(self.db_local)
            cursor = conexao.cursor()
            cursor.execute("SELECT tipo, conteudo, timestamp, remetente_real FROM mensagens WHERE contato = ? ORDER BY id ASC", (contato,))
            historico = cursor.fetchall()
            conexao.close()
            total = len(historico)
            indice_novas = total - nao_lidas
            for i, (tipo, conteudo, hora, rem_real) in enumerate(historico):
                if nao_lidas > 0 and i == indice_novas:
                    self.area_mensagens.insert(tk.END, "\n" + "—" * 15 + " NOVAS MENSAGENS " + "—" * 15 + "\n\n", 'separador')
                    self.ultimo_remetente = None
                rem_atual = "Você" if tipo == 'enviada' else (rem_real if rem_real else contato)
                self._inserir_na_tela(rem_atual, conteudo, hora, tipo == 'enviada')
        self.area_mensagens.yview(tk.END)
        self.area_mensagens.config(state='disabled')

    def renderizar_lista_contatos(self):
        t = self.c["dark"] if self.tema_escuro else self.c["light"]
        self.lista_contatos.delete(0, tk.END)
        for grupo_data in self.meus_grupos:
            grupo = grupo_data["nome"]
            nao_lidas = self.mensagens_nao_lidas.get(grupo, 0)
            tag = f"  👥 {grupo} ({nao_lidas})" if nao_lidas > 0 else f"  👥 {grupo}"
            self.lista_contatos.insert(tk.END, tag)
            cor = {'bg': '#DA373C', 'fg': 'white'} if nao_lidas > 0 else {'bg': t["bg_panel"], 'fg': t["fg_text"]}
            self.lista_contatos.itemconfig(tk.END, cor)

        for contato in self.contatos_status:
            nome = contato.get("username")
            status = contato.get("status")
            if nome != self.usuario_atual:
                nao_lidas = self.mensagens_nao_lidas.get(nome, 0)
                if nao_lidas > 0:
                    self.lista_contatos.insert(tk.END, f"  ● {nome} ({nao_lidas})")
                    self.lista_contatos.itemconfig(tk.END, {'bg': '#DA373C', 'fg': 'white'})
                elif status == "online":
                    self.lista_contatos.insert(tk.END, f"  ● {nome}")
                    self.lista_contatos.itemconfig(tk.END, {'bg': t["bg_panel"], 'fg': '#00a884'})
                else:
                    self.lista_contatos.insert(tk.END, f"  ○ {nome}")
                    self.lista_contatos.itemconfig(tk.END, {'bg': t["bg_panel"], 'fg': t["fg_muted"]})

    def selecionar_contato(self, event):
        selecao = self.lista_contatos.curselection()
        if not selecao: return
        texto_item = self.lista_contatos.get(selecao[0])
        self.is_group_atual = "👥" in texto_item
        nome_contato = texto_item.strip().split(maxsplit=1)[1]
        nome_contato = nome_contato.split('(')[0].strip() if '(' in nome_contato else nome_contato.strip()

        self.destinatario_atual = nome_contato
        self.ultimo_remetente = None
        self.is_admin_atual = False

        if self.is_group_atual:
            for g in self.meus_grupos:
                if g["nome"] == nome_contato:
                    self.is_admin_atual = (g.get("criador") == self.usuario_atual)
                    break

        self.label_chat_com.config(text=nome_contato)
        self.btn_fechar_chat.pack_forget()
        self.btn_sair_grupo.pack_forget()
        self.btn_add_membro.pack_forget()
        self.btn_remover_membro.pack_forget()
        self.btn_excluir_grupo.pack_forget()
        self.btn_fechar_chat.pack(side=tk.RIGHT, padx=15)

        if self.is_group_atual:
            if self.is_admin_atual:
                self.btn_excluir_grupo.pack(side=tk.RIGHT, padx=5)
                self.btn_remover_membro.pack(side=tk.RIGHT, padx=5)
                self.btn_add_membro.pack(side=tk.RIGHT, padx=5)
            else:
                self.btn_sair_grupo.pack(side=tk.RIGHT, padx=5)

        self.btn_enviar.config(state=tk.NORMAL)
        self.entry_mensagem.config(state=tk.NORMAL)
        if self.painel_emoji_aberto: self.alternar_painel_emoji()

        nao_lidas = self.mensagens_nao_lidas.get(nome_contato, 0)
        self.carregar_historico_na_tela(nome_contato, nao_lidas)
        self.mensagens_nao_lidas[nome_contato] = 0
        self.renderizar_lista_contatos()
        self.label_digitando.config(text="")


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatCliente(root)
    root.mainloop()