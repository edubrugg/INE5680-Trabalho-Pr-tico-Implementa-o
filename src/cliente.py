import json
from base64 import b64encode
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2

from src.servidor import Servidor, User

class Cliente:
  def __init__(self):
    self.usuarios = []
    self.servidor = Servidor()
    self.codigo_2fa_usado_no_login = ''
    self.pbkdf2_codigo_2fa_usado_no_login = ''


  def cadastrar(self):
    # Input do usuário
    print('-------------- Cadastro --------------')
    usuario = input('Informe o nome do usuário: ')
    senha = input('Informe a senha do usuário: ')
    print('\n')

    # Validação do nome do usuário
    if self.servidor.buscar_usuario(usuario) != None:
      print('Usuário já existente.')
      print('\n')
      return
    if not usuario:
      print('Por favor informe um nome válido para o usuário.')
      print('\n')
      return

    # Chama o servidor pra fazer o cadastro
    salt = usuario[::-1]
    chave_PBKDF2 = PBKDF2(senha, salt, 32, count=10000, hmac_hash_module=SHA512)
    self.servidor.cadastrar_usuario(usuario, chave_PBKDF2)
    print('Usuário ' + usuario + ' cadastrado!')
    print('\n')

  def login(self):
    # TODO
    print('--------------- Login ---------------')
    usuario = input('Usuário: ')
    senha = input('Senha: ')
    print('\n')

    # Busca o cadastro do usuário
    usuario_buscado = self.servidor.buscar_usuario(usuario)
    if usuario_buscado == None:
      print('Este usuário é inválido ou não está cadastrado.')
      print('\n')
      return

    salt = usuario[::-1]
    chave_PBKDF2 = PBKDF2(senha, salt, 32, count=10000, hmac_hash_module=SHA512)
    horario_formatado = datetime.now()
    sucesso_login = self.servidor.login(usuario_buscado, chave_PBKDF2, horario_formatado)
    if sucesso_login != False:
      self.codigo_2fa_usado_no_login = sucesso_login
      self.iniciar_comunicacao(usuario_buscado)

  def iniciar_comunicacao(self, usuario: User):
    # Criando as chaves, salt e mensagem que serão utilizadas na criptografia
    salt = usuario.nome_de_usuario[::-1]
    print('\n')
    codigo_pbkdf2 = PBKDF2(self.codigo_2fa_usado_no_login, salt, 32, count=10000, hmac_hash_module=SHA512)
    self.pbkdf2_codigo_2fa_usado_no_login = codigo_pbkdf2

    # Criando a interface de interação do usuário/cliente com o servidor
    while True:
      print('------------- Troca de mensagens ------------')
      print('          Para sair, digite \'Sair\'')
      print('---------------------------------------------')
      print('\n')
      message = input('Qual a mensagem a ser enviada? ')

      if message.lower() == 'sair':
        break

      # Encriptografando a mensagem
      cipher = AES.new(codigo_pbkdf2, AES.MODE_GCM)
      header = b'header'
      cipher.update(header)
      b_message = message.encode('utf-8')
      ciphertext, tag = cipher.encrypt_and_digest(b_message)

      json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
      json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag ]]
      mensagem_encriptografada = json.dumps(dict(zip(json_k, json_v)))

      # Enviando mensagem pro servidor
      print('\n')
      print('Mensagem criptografada enviada para o servidor: ', mensagem_encriptografada)
      print('\n')

      self.servidor.receber_mensagem(mensagem_encriptografada)


    
