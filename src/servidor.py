class User:
  def __init__(self, nome_de_usuario, hash_senha):
    self.nome_de_usuario = nome_de_usuario
    self.hash_senha = hash_senha

class Servidor:
  def __init__(self):
    self.usuarios = []

  def cadastrar(self):
    print('---------------Cadastro---------------')
    print('\n')
    usuario = input('Informe o nome do usuário: ')
    senha = input('Informe a senha do usuário: ')

  def login(self):
    print('---------------Cadastro---------------')
    print('\n')
    usuario = input('Informe o nome do usuário: ')
    senha = input('Informe a senha do usuário: ')
