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

#################################################################
# Software
import pandas as pd
from pygtail import Pygtail
import lib.carga
import lib.procesa
import os

__version__ = '0.1'
##matriz_de_datos = []

def start():
	"""
	Hace la carga inicial del proceso

	Parameters
	----------

	Returns
	-------
	
	"""
	# Indicadores, inicial vacío
	indicadores_atacantes = pd.DataFrame(columns=('Origen', 'Etapa', 'contador'))
	indicadores_hosts = pd.DataFrame(columns=('Destino', 'Etapa', 'contador'))
	indicadores_detalle = pd.DataFrame(columns=('Origen', 'Destino', 'Etapa', 'contador'))
	# Registro general de alertas ya clasificadas, inicial vacío
	repositorioAlertasClasificadas = pd.DataFrame(columns=('timestamp','SID','Etapa','Subetapa','Origen','Destino'))
	# Carga inicial de clasificacion de reglas 
	clasificacion = pd.read_csv(reglasClasificacion,encoding="latin-1",sep=";")
	lib.carga.crear_archivo_sid_sin_clasificar()

	if servicio:
		while True:
			run(repositorioAlertasClasificadas, clasificacion, indicadores_atacantes, indicadores_hosts, indicadores_detalle)
			time.sleep(5) # en segundos
	else:
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
	# Leer y procesa linea a linea. Pygtail solo lee lineas (alertas) nuevas
	for linea in Pygtail( archivoAlertas ):
	    alerta=lib.carga.separa(linea)
	    # Clasificar tipo (1,2,3,4); o null/vacia: si no es de interes o es imposible de clasificar
	    alertaClasificada=lib.carga.clasifica(alerta, clasificacion)
	    if ( not alertaClasificada is None ) and ( len(alertaClasificada.index) > 0 ): # Se procesa solo si no viene vacía
	    	repositorioAlertasClasificadas.append(alertaClasificada, ignore_index=True)
	    	indicadores_atacantes, indicadores_hosts, indicadores_detalle = lib.procesa.generaIndicadores(alertaClasificada, 
	    							indicadores_atacantes, indicadores_hosts, indicadores_detalle)

	 # Operacion final
	indicadores_atacantes.to_csv("indicadores_atacantes.csv", index=False)	
	indicadores_hosts.to_csv("indicadores_hosts.csv", index=False)
	indicadores_detalle.to_csv("indicadores_detalle.csv", index=False)

if __name__ == '__main__':
    start()