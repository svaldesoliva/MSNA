# genera_archivo_clasificacion_base.sh

Escrito en BASH, extrae los valores de las alertas y genera un CSV separado por ; a fin de entregar un 
archivo base donde se puedan agregar las clasificaciones de los archivos de forma comoda

# Salida
## Archivo
El archivo de salida se llama clasificacion_base.csv, aunque ese nombre configurable

## Campos
SID, Etapa, Subetapa, Observaciones, archivo, alerta
- SID, sid de la regla
- Etapa, en blanco para llenar
- Subetapa, en blanco para llenar
- Observaciones, en blanco para llenar
- tipo_destino, dato necesario para procesamiento en siguiente etapa. codigos: 1 HOME_NET / 2 EXTERNAL_NET / 0 DESCONOCIDO
- archivo, nombre del archivo que contiene la regla, indica tipo
- alerta, alerta como estaba escrita en el archivo salvo que su separacion por ; cambió por ,

