FROM ubuntu:24.04

# Evitar prompts interactivos durante la instalación
ENV DEBIAN_FRONTEND=noninteractive

# Instalación de Snort 2.9 y herramientas
# Ubuntu 24.04 (Noble) incluye Snort 2.9.20 en sus repositorios y Python 3.12
RUN apt-get update && apt-get install -y --no-install-recommends \
    snort \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    iproute2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configurar el directorio de trabajo
WORKDIR /app

# Copiar requirements.txt e instalar dependencias de Python
# Nota: En Ubuntu 24.04, pip puede requerir --break-system-packages si no se usa venv,
# pero en un contenedor dedicado esto es aceptable para simplificar.
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Crear directorios necesarios para Snort
RUN mkdir -p /etc/snort/rules /var/log/snort /usr/local/lib/snort_dynamicrules /etc/snort/map
