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
from progress.bar import Bar
import matplotlib.pyplot as plt


__version__ = '0.1'


def start():
	"""
	Hace la carga inicial del proceso

	Parameters
	----------

	Returns
	-------
	
	"""
	# Indicadores, inicial vacío
	indicadores_atacantes = pd.DataFrame(columns=('Remoto', 'Etapa', 'contador'))
	indicadores_hosts = pd.DataFrame(columns=('Local', 'Etapa', 'contador'))
	indicadores_detalle = pd.DataFrame(columns=('Remoto', 'Local', 'Etapa', 'contador'))
	# Registro general de alertas ya clasificadas, inicial vacío
	repositorioAlertasClasificadas = pd.DataFrame(columns=('timestamp','SID','Etapa','Subetapa','Remoto','Local'))
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
	if not servicio:
		f = open(archivoAlertas, 'r')
		bar1 = Bar('Procesando:', max=len(f.readlines()))
		f.close()

	# Leer y procesa linea a linea. Pygtail solo lee lineas (alertas) nuevas	
	for linea in Pygtail( archivoAlertas ):
	    alerta=lib.carga.separa(linea)
	    # Clasificar tipo (1,2,3,4); o null/vacia: si no es de interes o es imposible de clasificar
	    alertaClasificada=lib.carga.clasifica(alerta, clasificacion)
	    if ( not alertaClasificada is None ) and ( len(alertaClasificada.index) > 0 ): # Se procesa solo si no viene vacía
	    	repositorioAlertasClasificadas.append(alertaClasificada, ignore_index=True)
	    	indicadores_atacantes, indicadores_hosts, indicadores_detalle = lib.procesa.generaIndicadores(alertaClasificada, 
	    							indicadores_atacantes, indicadores_hosts, indicadores_detalle)

	    if not servicio:
	    	bar1.next()

		# Fin FOR

	if not servicio:
		bar1.finish()

	 # Operacion final
	indicadores_atacantes.sort_values(['Remoto', 'Etapa'], ascending=[True, True])
	indicadores_atacantes.to_csv("indicadores_atacantes.csv",encoding="latin-1",sep=";", index=False)	

	indicadores_hosts.sort_values(['Local', 'Etapa'], ascending=[True, True])
	indicadores_hosts.to_csv("indicadores_hosts.csv",encoding="latin-1",sep=";", index=False)

	indicadores_detalle.sort_values(['Remoto', 'Local', 'Etapa'], ascending=[True, True, True])
	indicadores_detalle.to_csv("indicadores_detalle.csv",encoding="latin-1",sep=";", index=False)

	"""
	indicadores_atacantes = pd.read_csv("indicadores_atacantes.csv",encoding="latin-1",sep=";")
	indicadores_hosts = pd.read_csv("indicadores_hosts.csv",encoding="latin-1",sep=";")
	indicadores_detalle = pd.read_csv("indicadores_detalle.csv",encoding="latin-1",sep=";")

#https://www.delftstack.com/es/howto/matplotlib/pandas-plot-multiple-columns-on-bar-chart-matplotlib/
#http://bl.ocks.org/ndarville/7075823

	l1=indicadores_hosts.query("Local == '192.168.100.128'")


	hosts=["192.168.100.128"]
	ataques={
	    "Ataques 1":[10],
	    "2":[20],
	    "3":[18],
	    "4":[18],
	}

	df=pd.DataFrame(ataques,index=hosts)
#	df.DataFrame({	'SID': sid }, index=[0])

	df.plot(kind="bar",stacked=True,figsize=(10,8))
	plt.legend(loc="lower left",bbox_to_anchor=(0.8,1.0))
	plt.show()	
"""

if __name__ == '__main__':
    start()