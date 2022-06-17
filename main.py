import inquirer
from src.servidor import Servidor

servidor = Servidor()

options = [
  inquirer.List('option',
                message="O que você deseja?",
                choices=['Login', 'Cadastrar', 'Sair'],
            ),
]
answers = inquirer.prompt(options)

print(answers['option'])

if answers['option'] == 'Login':
  print('Função de login')

elif answers['option'] == 'Cadastrar':
  servidor.cadastrar()

else:
  print('Função de sair')