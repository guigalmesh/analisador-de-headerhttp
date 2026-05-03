# =========================================================
# ETAPA 1: BUILDER (Compilação)
# =========================================================
FROM haskell:9.4-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. Sobrescreve a lista principal, MATA a pasta de listas extras e desativa a checagem de data
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && \
    rm -rf /etc/apt/sources.list.d/* && \
    echo "Acquire::Check-Valid-Until \"false\";" > /etc/apt/apt.conf.d/10no-check-valid-until

# 2. Agora sim, sem nenhum arquivo fantasma atrapalhando, o update vai funcionar
RUN apt-get update && apt-get install -y libsqlite3-dev zlib1g-dev pkg-config

WORKDIR /app

# 1. Copia o ficheiro .cabal
COPY *.cabal ./

# 2. Instala as dependências forçando 1 núcleo (-j1)
RUN cabal update && cabal build --dependencies-only -j1

# 3. Copia o resto do código fonte
COPY . .

# 4. Compila o projeto final usando 1 núcleo (-j1)
RUN cabal build -j1

# 5. Move o executável para o nome fixo "server-exe"
RUN cp $(cabal list-bin exe:analisador-de-headerhttp) /app/server-exe

# =========================================================
# ETAPA 2: RUNTIME (Execução)
# =========================================================
FROM debian:bullseye-slim

WORKDIR /app

# Instala o runtime do SQLite, certificados e o zlib1g para produção
RUN apt-get update && \
    apt-get install -y libsqlite3-0 ca-certificates zlib1g && \
    rm -rf /var/lib/apt/lists/*

# Copia o executável com o nome correto ("server-exe")
COPY --from=builder /app/server-exe .

RUN chmod +x ./server-exe

# Comando para iniciar a API (Agora batendo com o nome exato do arquivo!)
CMD ["./server-exe"]
