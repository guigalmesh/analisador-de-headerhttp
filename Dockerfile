# =========================================================
# ETAPA 1: BUILDER (Compilação)
# Usando a versão baseada no Debian 11 (Bullseye) para evitar erros 404
# =========================================================
FROM haskell:9.4-bullseye AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Instala SQLite, zlib e pkg-config direto dos repositórios oficiais vivos
RUN apt-get update && apt-get install -y libsqlite3-dev zlib1g-dev pkg-config

WORKDIR /app

# 1. Copia o ficheiro .cabal
COPY *.cabal ./

# 2. Instala as dependências forçando 1 núcleo (-j1) para proteger a RAM do Render
RUN cabal update && cabal build --dependencies-only -j1

# 3. Copia o resto do código fonte
COPY . .

# 4. Compila o projeto final usando 1 núcleo (-j1)
RUN cabal build -j1

# 5. Move o executável
RUN cp $(cabal list-bin exe:analisador-de-headerhttp) /app/server-exe

# =========================================================
# ETAPA 2: RUNTIME (Execução)
# =========================================================
FROM debian:bullseye-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libsqlite3-0 ca-certificates zlib1g && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/server-exe .

RUN chmod +x ./server-exe

CMD ["./server-exe"]
