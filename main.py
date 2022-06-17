from src.cliente import Cliente

cliente = Cliente()

while True:
  print('--------------- Menu ---------------')
  print('(1) Cadastro')
  print('(2) Login')
  print('(3) Sair')
  opcao = int(input('O que você deseja fazer? '))
  print('\n')

  funcoes = {
    1: cliente.cadastrar,
    2: cliente.login,
    3: quit
  }

  if opcao != 1 and opcao != 2 and opcao != 3:
    print('Por favor, digite uma opção válida')
  else:
    funcoes[opcao]()