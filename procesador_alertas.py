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
from pygtail import Pygtail
import lib.carga

__version__ = '0.1'
matriz_de_datos = []

def start():
	for linea in Pygtail( archivoAlertas ):
	    fila=lib.carga.separa(linea)
	    clasificacion=lib.carga.clasifica(fila)


if __name__ == '__main__':
    start()