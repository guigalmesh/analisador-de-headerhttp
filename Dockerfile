# =========================================================
# ETAPA 1: BUILDER (Compilação)
# =========================================================
FROM haskell:9.4 AS builder

# Instala a biblioteca de desenvolvimento do SQLite necessária para compilar o sqlite-simple
RUN apt-get update && apt-get install -y libsqlite3-dev

WORKDIR /app

# 1. Copia apenas o ficheiro .cabal para aproveitar a cache das dependências do Docker
COPY *.cabal ./

# 2. Actualiza o índice e instala as dependências (esta parte é a mais demorada)
RUN cabal update && cabal build --dependencies-only

# 3. Copia o resto do código fonte (Engine.hs, Main.hs, etc.)
COPY . .

# 4. Compila o projeto final
RUN cabal build

# 5. Move o executável para um local fixo.
# IMPORTANTE: Substitui 'nome-do-teu-projeto' pelo nome que definiste no ficheiro .cabal!
RUN cp $(cabal list-bin exe:analisador-de-headerhttp) /app/server-exe

# =========================================================
# ETAPA 2: RUNTIME (Execução)
# =========================================================
FROM debian:bullseye-slim

WORKDIR /app

# Instala apenas o runtime do SQLite e certificados para conexões HTTPS seguras
RUN apt-get update && \
    apt-get install -y libsqlite3-0 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copia o executável puro gerado na etapa anterior
COPY --from=builder /app/server-exe .

# O banco de dados history.db será criado automaticamente pelo teu initDB no arranque
# O Render injeta a variável PORT automaticamente, o teu Main.hs deve lê-la via lookupEnv

# Garante permissão de execução
RUN chmod +x ./server-exe

# Comando para iniciar a API
CMD ["./headereport-server"]
