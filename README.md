# LaserBox Secure Suite

Esta suíte foi criada para **proteger o seu `index.html` sem mexer no arquivo original**. O HTML original foi empacotado em um bundle criptografado, e o cliente final passa a usar um **launcher protegido por licença**.

## O que foi entregue

### 1) Builder/Admin (`admin/admin_builder.py`)
Painel para:
- cadastrar cliente
- salvar nome / razão social
- CPF ou CNPJ com máscara
- telefone com máscara
- CEP com máscara
- endereço completo
- gerar licenças por plano: mensal, trimestral, semestral, anual ou permanente
- vincular a licença ao **código de instalação** enviado pelo cliente
- limitar para **1 dispositivo**
- abrir o WhatsApp do cliente quando precisar cobrar renovação

### 2) Launcher do cliente (`client/client_launcher.py`)
Fluxo:
- ao instalar, o cliente abre o launcher
- o launcher mostra um **código de instalação**
- o cliente envia esse código para você
- você gera a licença no Builder
- o cliente cola a licença no launcher
- o launcher valida a assinatura digital, o dispositivo e o vencimento
- só então o sistema abre

### 3) Proteção do app
- o `index.html` foi transformado em `client/data/app.bundle`
- o cliente **não recebe o HTML aberto em texto puro** dentro do fluxo principal
- o launcher descriptografa o app e serve localmente apenas quando a licença é válida
- a licença é assinada com **ECDSA P-256 + SHA-256**
- o cliente recebe só a **chave pública**
- o Builder fica com a **chave privada**
- isso impede geração de chaves aleatórias válidas

## Estrutura

- `admin/admin_builder.py` → painel do administrador
- `admin/keys/private_key.pem` → **NÃO entregar ao cliente**
- `admin/keys/public_key.pem` → chave pública
- `admin/output/` → licenças geradas
- `client/client_launcher.py` → launcher protegido do cliente
- `client/keys/public_key.pem` → valida a licença
- `client/support_config.json` → telefone do WhatsApp e texto de ajuda
- `client/data/app.bundle` → app criptografado
- `shared/pack_original.py` → reempacota o HTML original
- `docs/index-original.html` → cópia do arquivo original para referência

## Como usar

### No seu PC (administrador)
1. Edite `client/support_config.json` e coloque seu número real de WhatsApp.
2. Abra `admin/admin_builder.py`.
3. Cadastre o cliente.
4. Peça para o cliente abrir `client/client_launcher.py`.
5. O cliente vai te passar o **código de instalação**.
6. Cole esse código no Builder.
7. Escolha o plano.
8. Gere a licença.
9. Envie o arquivo `.lic` para o cliente ou cole o JSON para ele.

### No PC do cliente
1. Abra `client/client_launcher.py`.
2. Copie o código de instalação.
3. Envie para o administrador.
4. Cole a licença recebida.
5. Clique em **Abrir sistema**.

## Renovação mensal
Você pode renovar da mesma forma:
- selecionar o cliente no Builder
- colar o código de instalação dele
- escolher o plano mensal
- gerar uma nova licença com novo vencimento

## Reempacotar quando trocar o HTML original
Se você atualizar o sistema principal:

```bash
python shared/pack_original.py CAMINHO_DO_INDEX.HTML client/data/app.bundle shared/bundle_key.bin
```

## Recomendações fortes para vender

### Entrega ao cliente
Entregue somente:
- pasta `client/`
- nunca entregue `admin/keys/private_key.pem`
- nunca entregue o Builder ao cliente

### Para dificultar engenharia reversa
Empacote como executável com PyInstaller:

```bash
pyinstaller --onefile --windowed client/client_launcher.py
pyinstaller --onefile --windowed admin/admin_builder.py
```

### Segurança realista
Nenhum sistema offline é 100% inviolável. Esta solução já eleva bastante a proteção porque:
- esconde o app original no bundle criptografado
- usa assinatura digital real
- trava a licença ao dispositivo
- impede chaves aleatórias
- controla vencimento por plano

Para segurança ainda maior, o próximo passo seria migrar a validação para um **servidor online** com ativação e revogação remota.

## Dependência

- Python 3.10+
- `cryptography`

Instalação:

```bash
pip install cryptography
```
