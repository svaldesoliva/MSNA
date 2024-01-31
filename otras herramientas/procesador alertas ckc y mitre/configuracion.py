#################################################################
# Configuración
archivoAlertas = "alert.csv"  # Copia local de alertas
#archivoAlertas = "/var/log/snort/alert.csv"  # Alertas en directorio donde se genera (linux), para lectura en linea

separadorAlertas = "," # separador de campos en archivo de alertas (ej; ";" o "," segun cnofiguración de salida de snort)

reglasClasificacion = "clasificacion.csv" #Archivo con reglas clasificadas

# ¿es Servicio ?	
# 	True:	leerá todo el archivo la primera vez, y lo restante cuando se ejecute de nuevo. 
#			Queda en loop. 
#   False:	leerá desde el inicio cada vez. sin loop
servicio = False 


# Carpeta web en donde se realizará la entrega de los datos
carpetaSalida = "salida/" #"html/data/"

# si es True, se basa en los archivos anteriores y solo obtiene nuevos graficos
SoloGraficas = False

# Red local - NO OPERATIVO!!!!!!!
redLocal="10.5.1.0/24"

# Donde se guardan sid (Snort ID) de alertas que no tienen etapa, sirve para asignarles una etapa
archivo_sid_sin_clasificar = "alertas_sin_clasificar.csv"

# Incluir o no a las alertas que no tienen clasificación ( True/False)
incluirNoClasificadas = True  