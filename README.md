# RSA CLI Didatico em TypeScript

Aplicacao de terminal (CLI) feita com Ink + React para demonstrar RSA de forma didatica, incluindo:

- geracao de chaves (manual e aleatoria)
- criptografia de texto UTF-8 por blocos
- descriptografia por texto ou por arquivo .rsa
- exportacao de saida em arquivos separados por tipo de operacao

## Visao Geral

O projeto implementa RSA usando bigint, sem bibliotecas externas de criptografia assimetrica pronta. Isso permite visualizar cada etapa matematica:

- escolha de p e q
- calculo de n e phi
- escolha de e coprimo de phi
- calculo de d como inverso modular de e
- criptografia e descriptografia por exponenciacao modular rapida

## Requisitos

- Node.js LTS (testado em 24.15.0)
- npm

## Instalacao

1. npm install

## Como executar

- modo desenvolvimento:
	npm run dev

- execucao equivalente:
	npm run start

- compilar TypeScript:
	npm run build

## Como usar no CLI

Ao iniciar, use:

- setas para navegar
- Enter para confirmar
- Esc para cancelar um formulario
- Ctrl+C para sair

Opcoes do menu:

1. Gerar chaves
2. Gerar chaves aleatoriamente
3. Informar chaves manualmente
4. Criptografar texto
5. Descriptografar texto
6. Descriptografar a partir de arquivo .rsa
7. Sair

### 1) Gerar chaves (p e q)

Voce informa dois primos distintos:

- p
- q

O sistema mostra um aviso sobre referencia para modulo alvo de 256 bits:

- para p e q com tamanhos parecidos, use cada primo acima de 2^128
- referencia pratica: pelo menos 129 bits por primo

### 2) Gerar chaves aleatoriamente

Voce informa a quantidade de bits por primo (intervalo atual do projeto: 5 a 16).

Observacao: esse intervalo e pequeno por ser didatico e rapido para testes, nao para seguranca real.

### 3) Informar chaves manualmente

Permite informar ou atualizar chaves publicas e privadas com campos opcionais.

Formatos aceitos para chave completa:

- publica: e:n (ou e,n / e;n)
- privada: d:n (ou d,n / d;n)

## Fluxo de Criptografia e Descriptografia

### Entrada e saida de texto

- entrada tratada como UTF-8
- texto convertido para bytes via TextEncoder
- retorno convertido para string via TextDecoder

### Criptografar texto

Ao criptografar:

1. o texto vira bytes UTF-8
2. os bytes sao divididos em blocos
3. cada bloco vira bigint (big-endian)
4. cada bloco e criptografado com c = m^e mod n
5. a saida final usa formato serializado por blocos

Formato dos blocos criptografados:

tamanho:valor|tamanho:valor|...

### Descriptografar texto

Ao descriptografar:

1. cada bloco tamanho:valor e lido
2. aplica m = c^d mod n
3. bigint volta para bytes no tamanho original
4. bytes sao remontados e decodificados em UTF-8

### Descriptografar a partir de arquivo .rsa

Nesta opcao, o CLI lista automaticamente os arquivos .rsa em outputs/encrypt.

- selecione o arquivo com setas para cima/baixo
- confirme com Enter
- opcionalmente exporte a saida descriptografada para novo arquivo

## Exportacao de Arquivos .rsa

As saidas sao separadas por pasta:

- criptografia: outputs/encrypt
- descriptografia: outputs/decrypt

Regras:

- voce informa apenas nome do arquivo
- extensao .rsa e aplicada automaticamente
- pastas sao criadas automaticamente quando necessario
- escrita de arquivos em UTF-8

## Como o calculo RSA e feito

Resumo matematico implementado:

1. n = p * q
2. phi = (p - 1) * (q - 1)
3. escolher e tal que 1 < e < phi e gcd(e, phi) = 1
4. calcular d como inverso modular de e modulo phi
5. chave publica = (e, n)
6. chave privada = (d, n)

Criptografia de bloco m:

c = m^e mod n

Descriptografia de bloco c:

m = c^d mod n

Detalhes de implementacao:

- gcd por algoritmo de Euclides
- inverso modular por Euclides estendido
- exponenciacao modular por quadrados sucessivos (modPow)

## Validacoes Importantes

- p e q devem ser primos
- p e q nao podem ser iguais
- n deve ser >= 256 para suportar texto UTF-8 no fluxo atual
- blocos devem respeitar 0 <= m < n

## Estrutura Principal do Projeto

- index.tsx: interface CLI e fluxo de interacao
- rsa.ts: geracao/validacao de chaves e utilitarios matematicos
- encrypt.ts: criptografia por blocos
- decrypts.ts: descriptografia por blocos

## Aviso de Seguranca

Este projeto tem foco educacional.

Nao use em producao para proteger dados sensiveis. Faltam componentes obrigatorios de RSA seguro moderno, como padding criptografico apropriado (exemplo: OAEP) e parametros de seguranca robustos.
