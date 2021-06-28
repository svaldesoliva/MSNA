#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

#
#
#

#################################################################
# Configuración
archivoAlertas = "alert.csv"  # Copia local de alertas
#archivoAlertas = "/var/log/snort/alert.csv"  # Alertas en directorio donde se genera (linux), para lectura en linea

reglasClasificacion = "clasificacion.csv" #Archivo con reglas clasificadas

# ¿es Servicio ?	
# 	True:	leerá todo el archivo la primera vez, y lo restante cuando se ejecute de nuevo. 
#			Queda en loop. 
#   False:	leerá desde el inicio cada vez. sin loop
servicio=False 


# Carpeta web en donde se realizará la entrega de los datos
carpetaSalida = "salida/" #"html/data/"

# si es True, se basa en los archivos anteriores y solo obtiene nuevos graficos
SoloGraficas=False

# Red local - NO OPERATIVO!!!!!!!
redLocal="10.5.1.0/24"

#################################################################
# Software
import pandas as pd
from pygtail import Pygtail
import lib.carga
import lib.procesa
import os
from progress.bar import Bar


__version__ = '0.9'


def start():
	"""
	Hace la carga inicial del proceso

	Parameters
	----------

	Returns
	-------
	
	"""
	# Indicadores, inicial vacío
	indicadores_atacantes = pd.DataFrame(columns=('Remoto', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	indicadores_hosts = pd.DataFrame(columns=('Local', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	indicadores_detalle = pd.DataFrame(columns=('Remoto', 'Local', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	# Registro general de alertas ya clasificadas, inicial vacío
	repositorioAlertasClasificadas = pd.DataFrame(columns=('timestamp','SID','Etapa','Subetapa','Remoto','Local', 'Alerta'))
	# Carga inicial de clasificacion de reglas 
	clasificacion = pd.read_csv(reglasClasificacion,encoding="latin-1",sep=";")
	lib.carga.crear_archivo_sid_sin_clasificar()

	if servicio:
		while True:
			run(repositorioAlertasClasificadas, clasificacion, indicadores_atacantes, indicadores_hosts, indicadores_detalle)
			time.sleep(5) # en segundos
	else:
		total_reglas = len(clasificacion.index) 
		alertas_conClasificacionUtil=clasificacion.query("Etapa==1 or Etapa==2 or Etapa==3 or Etapa==4")
		total_reglasUtil = len(alertas_conClasificacionUtil.index)
		alertas_conClasificacionUtil=pd.DataFrame() #vaciamos el resultado
		print("Reglas: " + str(total_reglasUtil) + "/" + str(total_reglas))
		# Si no es servicio, reiniciamos la lectura de las alertas
		if os.path.exists( archivoAlertas + ".offset"):
			os.remove( archivoAlertas + ".offset")
		run(repositorioAlertasClasificadas, clasificacion, indicadores_atacantes, indicadores_hosts, indicadores_detalle)


def run(repositorioAlertasClasificadas, clasificacion, indicadores_atacantes, indicadores_hosts, indicadores_detalle):
	"""
	Orquesta la ejecución del proceso

	Parameters
	----------
	repositorioAlertasClasificadas: Dataframe
		Panda Dataframe que contiene las alertas previamente clasificadas, para poder buscar detalle de ser necesario
	clasificacion : Dataframe
		Panda Dataframe que contiene los tipos de alerta definidos, que incluye el SID y la etapa de CKC correspondiente 
	indicadores_atacantes: Dataframe
		Indicadores de avance del ataque, conteo por atacante
	indicadores_hosts: Dataframe
		Indicadores de avance del ataque, conteo por host o victima
	indicadores_detalle: Dataframe
		Indicadores de avance del ataque, conteo cruzado a modo de detalle precalculado
	Returns
	-------
	
	"""
	if ( SoloGraficas == False ):
		if not servicio: #Leemos la cantidad de lineas para ver el avance
			f = open(archivoAlertas, 'r')
			operaciones=len(f.readlines())
			f.close()
			bar1 = Bar('Procesando:', max=operaciones, suffix = ' %(index)d/%(max)d - remanente %(eta)ds   ')
		contadorGrupo = 0
		# Leer y procesa linea a linea. Pygtail solo lee lineas (alertas) nuevas	
		for linea in Pygtail( archivoAlertas ):
			alerta=lib.carga.separa(linea)
			# Clasificar tipo (1,2,3,4); o null/vacia: si no es de interes o es imposible de clasificar
			alertaClasificada=lib.carga.clasifica(alerta, clasificacion, repositorioAlertasClasificadas, redLocal)
			if ( not alertaClasificada is None ) and ( len(alertaClasificada.index) > 0 ): # Se procesa solo si no viene vacía
				##repositorioAlertasClasificadas.append(alertaClasificada, ignore_index=True)
				## 'timestamp','SID','Etapa','Subetapa','Remoto','Local'
				repositorioAlertasClasificadas.loc[len(repositorioAlertasClasificadas.index)] = [alertaClasificada["timestamp"].item(), alertaClasificada["SID"].item(), alertaClasificada["Etapa"].item(), alertaClasificada["Subetapa"].item(), alertaClasificada["Remoto"].item(), alertaClasificada["Local"].item(), alertaClasificada["Alerta"].item()]
				indicadores_atacantes, indicadores_hosts, indicadores_detalle = lib.procesa.generaIndicadores(alertaClasificada, indicadores_atacantes, indicadores_hosts, indicadores_detalle)
				if servicio: #Guarda avance, genera indicadores graficos x grupo para mostrar avance 
					contadorGrupo = contadorGrupo + 1
					if ( contadorGrupo > 2000 ):
						contadorGrupo = 0
						repositorioAlertasClasificadas.to_csv(carpetaSalida + "alertas_clasificadas.csv",encoding="latin-1",sep=";", index=False)
						indicadores_atacantes.sort_values(['Etapa 1'], ascending=[False])
						indicadores_atacantes.to_csv(carpetaSalida + "indicadores_atacantes.csv",encoding="latin-1",sep=";", index=False)	
						indicadores_hosts.sort_values(['Etapa 1'], ascending=[False])
						indicadores_hosts.to_csv(carpetaSalida + "indicadores_hosts.csv",encoding="latin-1",sep=";", index=False)
						indicadores_detalle.sort_values(['Etapa 1'], ascending=[False])
						indicadores_detalle.to_csv(carpetaSalida + "indicadores_detalle.csv",encoding="latin-1",sep=";", index=False)
						lib.procesa.generaGraficos( "indicadores_atacantes.csv", "indicadores_hosts.csv",  "indicadores_detalle.csv", "alertas_clasificadas.csv", carpetaSalida )
			#Fin Si (Se procesa solo si no viene vacía)
			if not servicio:
				bar1.next()
		# Fin FOR / ciclo terminado
		if not servicio:
			bar1.finish()
		# Proceso final de indicadores
		repositorioAlertasClasificadas.to_csv(carpetaSalida + "alertas_clasificadas.csv",encoding="latin-1",sep=";", index=False)
		indicadores_atacantes.sort_values(['Etapa 1'], ascending=[False])
		indicadores_atacantes.to_csv(carpetaSalida + "indicadores_atacantes.csv",encoding="latin-1",sep=";", index=False)	
		indicadores_hosts.sort_values(['Etapa 1'], ascending=[False])
		indicadores_hosts.to_csv(carpetaSalida + "indicadores_hosts.csv",encoding="latin-1",sep=";", index=False)
		indicadores_detalle.sort_values(['Etapa 1'], ascending=[False])
		indicadores_detalle.to_csv(carpetaSalida + "indicadores_detalle.csv",encoding="latin-1",sep=";", index=False)
		if not servicio: #Mostramos por pantalla
			print("indicadores atacantes")
			print(indicadores_atacantes)
			print("indicadores hosts")
			print(indicadores_hosts)
			print("indicadores detalle")
			print(indicadores_detalle)

		#https://www.delftstack.com/es/howto/matplotlib/pandas-plot-multiple-columns-on-bar-chart-matplotlib/
		#http://bl.ocks.org/ndarville/7075823

	# Fin / if SoloGraficas

	if not servicio:
		print("Generando graficos")
	lib.procesa.generaGraficos( "indicadores_atacantes.csv", "indicadores_hosts.csv",  "indicadores_detalle.csv", "alertas_clasificadas.csv", carpetaSalida )

	#""

if __name__ == '__main__':
    start()