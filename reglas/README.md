# genera_archivo_clasificacion_base.sh

Escrito en BASH, extrae los valores de las alertas y genera un CSV separado por ; a fin de entregar un 
archivo base donde se puedan agregar las clasificaciones de los archivos de forma comoda

# Salida
## Archivo
El archivo de salida se llama clasificacion_base.csv aun que es configurable

## Campos
- SID, sid de la regla
- ID_Clasificacion, en blanco para llenar
- nombre_clasificacion, en blanco para llenar
- archivo, nombre del archivo que contiene la regla, indica tipo
- alerta, alerta como estaba escrita en el archivo salvo que su separacion por ; cambió por ,

