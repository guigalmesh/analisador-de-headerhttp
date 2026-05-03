# =========================================================
# ETAPA 1: BUILDER (Compilação)
# =========================================================
FROM haskell:9.4-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. Configura o repositório histórico (Buster) para evitar o Erro 404
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && \
    rm -rf /etc/apt/sources.list.d/* && \
    echo "Acquire::Check-Valid-Until \"false\";" > /etc/apt/apt.conf.d/10no-check-valid-until

# 2. A BALA DE PRATA: Removemos a biblioteca conflitante antes de instalar a nova!
RUN apt-get update && \
    apt-get remove -y libsqlite3-0 && \
    apt-get install -y libsqlite3-dev zlib1g-dev pkg-config

WORKDIR /app

# 3. Copia o .cabal e baixa as bibliotecas (Protegendo a memória do Render com -j1)
COPY *.cabal ./
RUN cabal update && cabal build --dependencies-only -j1

# 4. Copia o resto do código e compila
COPY . .
RUN cabal build -j1

# 5. Salva o binário com nome padrão
RUN cp $(cabal list-bin exe:analisador-de-headerhttp) /app/server-exe

# =========================================================
# ETAPA 2: RUNTIME (Execução)
# =========================================================
FROM debian:bullseye-slim

WORKDIR /app

# Instala os pacotes necessários para a produção
RUN apt-get update && \
    apt-get install -y libsqlite3-0 ca-certificates zlib1g && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/server-exe .

RUN chmod +x ./server-exe

CMD ["./server-exe"]
