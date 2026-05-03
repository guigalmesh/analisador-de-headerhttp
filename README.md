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
Então comecei a escrever um motor de regras para conseguir resolver esse problema, onde faço uma análise para cada cabeçalho e escrevo se é vulnerável ou não. Cada cabeçalho é considerado "Critical", "Recommended" ou "Other", dependendo da sua importância. As descrições de cada header eu tirei do OWASP.

Depois comecei a fazer o banco de dados, não foi muito complicado, escolhi salvar apenas um resumo da análise e não o JSON inteiro. Criei outros 2 endpoints para o banco de dados, um post e um get. Uma escolha de implementação também foi manter apenas uma análise por site, sempre que uma análise é feita de um mesmo site, é sobreescrito no banco de dados.

Uma parte difícil foi criar o ranking para cada site. Eu decidi fazer a avaliação no front-end, dando nota de A à F para cada site, o problema foi que de início todos os sites recebiam F. Isso acredito que se dá por várias razões, a principal é que ninguém confia apenas nos headers de segurança, as aplicações costumam usar defesa por profundidade, o que significa que mesmo que um header esteja ausente ou tenha configurações "frouxas", isso não expõe diretamente a vulnerabilidades. Também tem outros motivos como compatibilidade, especificidades de implementação, etc.

Deixei os testes por último, foi a única coisa para qual eu usei um agente, o que eu acho que foi um erro por que ele acabou alterando muita coisa que eu não pedi, tipo criando um novo arquivo .hs só para o banco de dados, que estava no Main.hs. Resolvi fazer assim por que vi um vídeo do Uncle Bob falando que uma das melhores aplicações da IA é justamente conseguir fazer esses testes de forma mais fácil.

---

## 4. Testes

Os testes fiz usando o HUnit, utilizei o prório chat do VScode usando o GPT-5 mini Medium como agente. Primeiro usei o modo de planejamento e depois pedi pra ele fazer um test-suite que englobasse minhas funções puras e meu banco de dados, ele acabou fazendo muita bagunça e mudando coisas que eu não pedi. Também surgiram alguns erros no meu código que não estavam lá antes. E ele não testou todas as funções também como eu pedi. Organizei tudo em outra pasta na root chamada test com um arquivo só pra ele (Spec.hs)

---

## 5. Execução

Rodar localmente:
- GHC e Cabal
- Dependências do OS no Debian: sudo apt install libsqlite3-dev zlib1g-dev pkg-config
- Pro front-end, qualquer servidor HTTP simples
- Para iniciar a API: cabal update -> cabal build -> cabal run

---

## 6. Deploy

Link do serviço publicado: <https://headerreport.onrender.com/>

Fiz o deploy pelo render.com mesmo. Ai fui usando a IA para ir configurando o arquivo Docker, foi muito complicado, devo ter tentado dar deploy umas 20 vezes.
O deploy do back-end e front-end foram feitos separados, o back como web service e o front como static site.


---

## 7. Resultado final

[Vídeo apresentando o site](apresentacao.gif)

---

## 8. Uso de IA

### 8.1 Ferramentas de IA utilizadas

Utilizei o Gemini 3.1 Pro para maioria das coisas e o GPT-5 mini como agente para os testes.

---

### 8.2 Interações relevantes com IA

Inclua **de 3 a 5 interações relevantes** com ferramentas de IA.


#### Interação 1

- **Objetivo da consulta:** Manter apenas uma conversa com a IA para que ela tivesse o contexto e definir como eu queria a ajuda
- **Trecho do prompt ou resumo fiel:**
"I'm making a project in Haskell. It's a header analyzer. It scans for the presence of security headers on a website (the user provides the URL). This is the chat where I'm going to ask questions about the project. My aim is to build it with the least AI help possible so I'm going to ask just especific questions. I do not want you to give me the answer directly, instead just point me in the right direction."
- **O que foi aproveitado:** A IA perdeu o contexto rapidamente e começou a dar a resposta completa
- **O que foi modificado ou descartado:**

#### Interação 2

- **Objetivo da consulta:** Decidir se era melhor usar String ou Text
- **Trecho do prompt ou resumo fiel:**
Pode me explicar de novo a diferença entre String e Text?
- **O que foi aproveitado:** Decidi usar o Text já que ele é sequencial na memória e por isso seria melhor pro projeto
- **O que foi modificado ou descartado:**

#### Interação 3

- **Objetivo da consulta:** Entender como eu poderia analisar a configuração da header
- **Trecho do prompt ou resumo fiel:**
"Mais perguntas: A presença de uma security header é uma coisa, mas há diferentes maneiras de configurá-la. Como seria fazer a análise da configuração da header (do valor)?"
- **O que foi aproveitado:** Me baseei na função "auditarCabecalho" que foi retornado e manti basicamente o mesmo padrão só adicionei mais headers e mudei algumas formas de analisar
- **O que foi modificado ou descartado:**

#### Interação 4 (opcional)

- **Objetivo da consulta:** Melhorar a experiência do usuário quando inserindo o site
- **Trecho do prompt ou resumo fiel:**
"No momento, eu preciso digitar o https:// sempre que for fazer uma busca. Não existe a opção de preencher automaticamente para o usuário caso ele digite apenas o link (facebook.com e não https://facebook.com). E como isso implicaria no funcionamento do código, já que muitos sites possuem redirecionamento quando acessado em protocolos diferentes?"
- **O que foi aproveitado:** Eu pretendia fazer isso no back-end, mas o Gemini sugeriu deixar isso apenas no front-end já que é parte de UI/UX
- **O que foi modificado ou descartado:**

#### Interação 5 (opcional)

- **Objetivo da consulta:** Fiz várias perguntas enviando algum erro que o compilador tenha me dado, perguntando o que era e como consertar
- **Trecho do prompt ou resumo fiel:**
[erro retornado pelo compilador]
- **O que foi aproveitado:** Geralmente levava uns 2/3 prompts para a IA acertar o que estava de errado e corrigir
- **O que foi modificado ou descartado:** Muitas vezes ela perdia o contexto e sugeria fixes que não faziam sentido no projeto

---

### 8.3 Exemplo de erro, limitação ou sugestão inadequada da IA

- Muitos erros aconteceram quando estava fazendo o front-end. Principalmente por que como eu não estava usando agente nem nenhum tipo de arquivo de configuração ele perdia o contexto e não deixava o projeto padronizado (principalmente no HTML que ficava muito bagunçado), a maior parte da padronização tive que fazer na mão.
- Ao usar um agente para implementar os testes, ele errou muitas vezes e passou +/- uns 15 minutos em loop testando e fazendo alterações no meu código, também alterando coisas que eu não pedi, dividindo os arquivos e no fim ainda não fez uma cobertura 100% com testes.

---

### 8.4 Comentário pessoal sobre o processo envolvendo IA

Eu acho que ajuda muito, principalmente para escrever um projeto complexo em uma linguagem que não tenho muito conhecimento. O front-end fiz todo praticamente usando IA. Mas acho que afeta um pouco o entendimento e o código fica muito bagunçado caso vá só copiando e colando o que a IA entrega. Mas consegui compreender melhor questões sobre a usabilidade do site. Mas atrapalha quando o projeto fica tão complexo que é díficil fazer alterações sem pedir para a IA.

---

## 9. Referências e créditos

securityheaders.com <br>
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html <br>
https://owasp.org/www-community/Security_Headers <br>
https://hackage-content.haskell.org/package/scotty-0.30/docs/Web-Scotty.html <br>
https://hackage.haskell.org/package/aeson-2.2.3.0/docs/Data-Aeson.html <br>
