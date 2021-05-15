#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

#
#
#

# Configuración
archivoAlertas = "alert.csv"
#archivoAlertas = "/var/log/snort/alert.csv"

reglasClasificacion = "clasificacion.csv"

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

	# Durante el desarrollo, reiniciamos la lectura de las alertas
	if os.path.exists("alert.csv.offset"):
	    os.remove("alert.csv.offset")

	# Leer linea a linea en la medida que aparezcan, como un servicio. Pygtail solo lee lineas (alertas) nuevas
	for linea in Pygtail( archivoAlertas ):
	    alerta=lib.carga.separa(linea)
	    alertaClasificada=lib.carga.clasifica(alerta, clasificacion)


if __name__ == '__main__':
    start()