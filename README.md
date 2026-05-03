# Analisador de Headers HTTP
# Backend Web com Haskell+Scotty


- Estrutura e conteúdo do README:


  3. Processo de desenvolvimento: comentários pessoais sobre o desenvolvimento, com evidências de compreensão, incluindo versões com erros e tentativas de solução
  4. Orientações para execução: instalação de dependências, etc.
  5. Resultado final: demonstrar execução em GIF animado ou vídeo curto (máximo 60s)
  6. Referências e créditos (incluindo alguns prompts, se aplicável)

## 1. Identificação

- Nome: Guilherme de Cezaro Martini
- Curso: Sistemas de Informação

---

## 2. Tema/objetivo

O tema foi criar um serviço web que receba uma URL e faça uma requisição pedindo apenas pelo cabeçalho do site. Ele analisa a presença de certas chaves que são relevantes para a segurança da informação, gerando um relatório JSON que é renderizado em cards no front-end. O back-end também possui um motor de regras que além de avaliar apenas a presença, também procura por más configurações dos valores em cada chave.
O objetivo desse site é auxiliar no mapeamento da superfície de defesa de aplicações web.
A permanência de dados foi feita usando o banco de dados sqlite, para salvar o URL do site, um sumário da análise, uma nota e a data da análise. O back-end também retorna um ranking com os sites mais bem avaliados no topo.

Já existe um um site que faz isso bem melhor (securityheaders.com) mas eu queria implementar algumas coisas diferentes, mas acabei não tendo tempo para diferenciar muito.

---

## 3. Processo de desenvolvimento

Comecei querendo fazer algo relacionado a cibersegurança, por que estou estudando o tema. Um tempo atrás tinha visto esse site e achei interessante.
Comecei tentando fazer o primeiro endpoint que recebia uma URL e fazia uma requisição, devolvendo um JSON estruturado com todos os cabeçalhos do site, e ai fui refinando isso para a requisição ser apenas do cabeçalho ("HEAD"), filtrar apenas os cabeçalhos interessantes e separar entre pares de chave e valor.
Depois me deparei com um problema: apenas avaliar a presença ou ausência de cabeçalhos não era o suficiente para fazer muita coisa. Por exemplo, algum cabeçalho podia estar presente mas mal configurado, alguns cabeçalhos mais novos "sobreescrevem" cabeçalhos antigos, o recomendado para outros é que eles estejam ausentes, entre outras coisas.
Então comecei a escrever um motor de regras para conseguir resolver esse problema, onde faço uma análise
Comente o processo de desenvolvimento do trabalho, com evidências de compreensão e de construção incremental.

Procure incluir, quando aplicável:

- como a ideia inicial evoluiu
- decisões tomadas ao longo do desenvolvimento
- erros encontrados
- dificuldades específicas enfrentadas
- tentativas de solução
- mudanças de rumo
- comentários pessoais sobre o que você compreendeu no processo e sobre questões que ainda persistem
- como você separou a lógica do serviço da parte ligada ao Scotty
- quais funções puras e estruturas de dados foram importantes no trabalho
- quais aspectos de programação funcional apareceram no desenvolvimento

Este não é um espaço para escrever algo como "foi difícil mas superei as dificuldades". O objetivo é mostrar sinais reais de desenvolvimento, reflexão, aprendizado e resolução de problemas.

Se o desenvolvimento não conseguir atingir todos os objetivos e requisitos, essa seção é muito importante para mostrar o que você tentou.

---

## 4. Testes

Descreva brevemente como você lidou com os testes unitários das funções que implementam a lógica do serviço, independentemente do Scotty.

Inclua, se necessário:

- quais funções puras foram testadas;
- como os testes foram organizados;
- se você usou HUnit ou outro modo simples de teste;
- exemplos curtos do que foi verificado.

Lembre que não se trata de testar se o serviço funciona pela web, mas sim de testar as funções puras que implementam a lógica.

---

## 5. Execução

Explique como executar o projeto, incluindo informações sobre dependências necessárias, comandos para compilar ou executar, etc.

---

## 6. Deploy

Link do serviço publicado: <complete aqui>

Descreva de forma breve como você realizou o deploy a partir da base e das orientações fornecidas. Caso não tenha conseguido, explique o que tentou.

---

## 7. Resultado final

Apresente o resultado final do trabalho, na forma de GIF animado ou vídeo curto (máximo 60s)

Você também pode acrescentar uma breve explicação sobre o que está sendo demonstrado.

---

## 8. Uso de IA

### 8.1 Ferramentas de IA utilizadas

Liste as principais ferramentas de IA utilizadas, com suas versões/modelos/planos. Por exemplo, ChatGPT Free com GPT-5.2 Thinking, GitHub Copilot com Gemini 2.0 Flash, Antigravity com Claude Sonnet 4.6 (Thinking), etc.

---

### 8.2 Interações relevantes com IA

Inclua **de 3 a 5 interações relevantes** com ferramentas de IA.


#### Interação 1

- **Objetivo da consulta:**
- **Trecho do prompt ou resumo fiel:**
- **O que foi aproveitado:**
- **O que foi modificado ou descartado:**

#### Interação 2

- **Objetivo da consulta:**
- **Trecho do prompt ou resumo fiel:**
- **O que foi aproveitado:**
- **O que foi modificado ou descartado:**

#### Interação 3

- **Objetivo da consulta:**
- **Trecho do prompt ou resumo fiel:**
- **O que foi aproveitado:**
- **O que foi modificado ou descartado:**

#### Interação 4 (opcional)

- **Objetivo da consulta:**
- **Trecho do prompt ou resumo fiel:**
- **O que foi aproveitado:**
- **O que foi modificado ou descartado:**

#### Interação 5 (opcional)

- **Objetivo da consulta:**
- **Trecho do prompt ou resumo fiel:**
- **O que foi aproveitado:**
- **O que foi modificado ou descartado:**

---

### 8.3 Exemplo de erro, limitação ou sugestão inadequada da IA

Descreva **ao menos um caso** em que a IA:

- errou
- foi incompleta
- sugeriu algo inadequado ou incompreensível
- produziu código que precisou de correção relevante

Explique brevemente o que aconteceu e como você percebeu ou corrigiu o problema.

---

### 8.4 Comentário pessoal sobre o processo envolvendo IA

Escreva um breve comentário pessoal sobre o processo envolvendo IA.

Você pode comentar, por exemplo:

- algo que passou a compreender melhor
- uma dificuldade que conseguiu superar
- uma limitação que ainda sente
- como o uso de IA ajudou ou atrapalhou em certos momentos.

---

## 9. Referências e créditos

Liste referências e créditos de forma detalhada, com título e URL, incluindo, quando aplicável:

- sites consultados
- documentações
- materiais de aula
- colegas
- trechos de código adaptados
- imagens, vídeos

Exemplo:

- Documentação do Scotty: ...
- Documentação do Render: ...
- Material de aula da disciplina: ...
- Vídeo sobre Scotty: ...
