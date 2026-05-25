# Docker para Snort 2.9 (MSNA)

Este directorio contiene la configuración para levantar una instancia de Snort 2.9 usando Docker (basado en **Debian Slim**), optimizada para ser ligera y funcional con los scripts de este repositorio.

## Requisitos
*   Docker
*   Docker Compose

## Instrucciones de uso

### 1. Construir la imagen
Desde la raíz del repositorio, ejecuta:
```bash
docker-compose -f docker/docker-compose.yml build
```

### 2. Iniciar el contenedor
```bash
docker-compose -f docker/docker-compose.yml up -d
```

### 3. Ejecutar el procesamiento de alertas
Para procesar archivos PCAP que tengas en el repositorio (por ejemplo en `05 experimento/`):
```bash
docker exec -it snort-msna bash
cd "05 experimento/DARPA Intrusion Detection Evaluation - LLDOS 1.0 - Scenario One"
python3 ../../"02 extraer alertas"/procesa_snort.py
```

## Notas sobre la configuración
*   El archivo `snort.conf` se genera automáticamente para incluir todas las reglas presentes en `01 genera template de reglas clasificacion/rules`.
*   Las reglas y mapas se montan como volúmenes, por lo que cualquier cambio en las reglas del repo se reflejará dentro del contenedor.
*   Las alertas se generan en formato CSV en `/var/log/snort/alert.csv` dentro del contenedor.
