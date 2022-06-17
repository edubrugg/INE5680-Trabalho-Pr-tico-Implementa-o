from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

from src.servidor import Servidor

class Cliente:
  def __init__(self):
    self.usuarios = []
    self.servidor = Servidor()

  def cadastrar(self):
    # Input do usuário
    print('---------------Cadastro---------------')
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
    print('---------------Cadastro---------------')
    usuario = input('Informe o nome do usuário: ')
    senha = input('Informe a senha do usuário: ')
    print('\n')
