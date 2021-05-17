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
	# Carga inicial de clasificacion de reglas 
	clasificacion = pd.read_csv(reglasClasificacion,encoding="latin-1",sep=";")
	lib.carga.crear_archivo_sid_sin_clasificar()

	if servicio:
		while True:
			run(clasificacion)
			time.sleep(60)
	else:
		# Si no es servicio, reiniciamos la lectura de las alertas
		if os.path.exists( archivoAlertas + ".offset"):
			os.remove( archivoAlertas + ".offset")
		run(clasificacion)


def run(clasificacion):
	"""
	Orquesta la ejecución del proceso

	Parameters
	----------
	clasificacion : Dataframe
		Panda Dataframe que contiene los tipos de alerta definidos, que incluye el SID y la etapa de CKC correspondiente 
	Returns
	-------
	
	"""
	# Leer y procesa linea a linea. Pygtail solo lee lineas (alertas) nuevas
	for linea in Pygtail( archivoAlertas ):
	    alerta=lib.carga.separa(linea)
	    alertaClasificada=lib.carga.clasifica(alerta, clasificacion)

if __name__ == '__main__':
    start()