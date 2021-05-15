#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

#
#
#

# Configuración
archivoAlertas = "alert.csv"  # Copia local de alertas
#archivoAlertas = "/var/log/snort/alert.csv"  # Alertas en directorio donde se genera, para lectura en linea

reglasClasificacion = "clasificacion.csv"

# Si es servicio: leerá todo el archivo la primera vez, y lo restante cuando se ejecute de nuevo. Queda en loop. 
#    No         : leerá desde el inicio cada vez.
servicio=False 

# Software
import pandas as pd
from pygtail import Pygtail
import lib.carga
import os

__version__ = '0.1'
matriz_de_datos = []

def start():
	# Carga inicial de clasificacion de reglas 
	clasificacion = pd.read_csv(reglasClasificacion,encoding="latin-1",sep=";")

	# Si no es servicio, reiniciamos la lectura de las alertas
	if !servicio && os.path.exists( archivoAlertas + ".offset"):
	    os.remove( archivoAlertas + ".offset")

	if servicio
		while True:
			run()
			time.sleep(60)
	else
		run()

def run():
	# Leer linea a linea. Pygtail solo lee lineas (alertas) nuevas
	for linea in Pygtail( archivoAlertas ):
	    alerta=lib.carga.separa(linea)
	    alertaClasificada=lib.carga.clasifica(alerta, clasificacion)

if __name__ == '__main__':
    start()