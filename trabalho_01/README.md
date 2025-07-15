# 🌟 Segurança da Computação - Instituto Federal de Brasília 🌟

# Criptografia com Streamlit

Este projeto é uma aplicação web desenvolvida com Streamlit que permite aos usuários criptografar e descriptografar textos usando algoritmos de criptografia simétrica (DES, AES) e assimétrica (RSA). A aplicação oferece uma interface amigável para gerar chaves, inserir textos e visualizar os resultados da criptografia e descriptografia.

## Estrutura do Projeto

```
trabalho_01
├── src
│   ├── __init__.py
│   ├── app.py          # Ponto de entrada da aplicação Streamlit
│   ├── crypto_utils.py # Funções utilitárias para operações criptográficas
│   └── ui.py          # Gerenciamento da interface do usuário
├── requirements.txt    # Dependências do projeto
└── README.md           # Documentação do projeto
```

## Pré-requisitos

Antes de executar a aplicação, você precisa ter o Python instalado em sua máquina. É recomendável usar um ambiente virtual para gerenciar as dependências do projeto.

## Instalação

1. Clone o repositório:

   ```
   git clone <URL_DO_REPOSITORIO>
   cd ifb_seg/trabalho_01
   ```

2. Crie um ambiente virtual (opcional, mas recomendado):

   ```
   python -m venv venv
   source venv/bin/activate  # Para Linux/Mac
   venv\Scripts\activate     # Para Windows
   ```

3. Instale as dependências:

   ```
   pip install -r requirements.txt
   ```

## Uso

Para iniciar a aplicação, execute o seguinte comando:

```
streamlit run src/app.py
```

Isso abrirá a aplicação em seu navegador padrão. Você poderá escolher o algoritmo de criptografia desejado, inserir o texto e as chaves, e visualizar os resultados da criptografia ou descriptografia.