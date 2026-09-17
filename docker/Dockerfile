FROM eclipse-temurin:21-jdk-jammy

ARG GHIDRA_ZIP=ghidra_12.1.3_PUBLIC_20260817.zip
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip

RUN apt-get update && apt-get install -y --no-install-recommends unzip curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fL -o /tmp/ghidra.zip "${GHIDRA_URL}"

RUN echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.3_PUBLIC
ENV PATH="${GHIDRA_INSTALL_DIR}/support:${PATH}"

WORKDIR /work
