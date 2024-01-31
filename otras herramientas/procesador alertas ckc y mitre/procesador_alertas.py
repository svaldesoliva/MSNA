#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

#
#
#


#################################################################
# Configuración
from configuracion import *

#################################################################
# Software
import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'
from pygtail import Pygtail
import lib.carga
import lib.procesa
import os
from progress.bar import Bar
import numpy as np

__version__ = '0.95'
col_list =  [ 'timestamp','SID','Etapa','Subetapa','tecnica1','tecnica2','tecnica3','Remoto','Local', 'Alerta' ]

def start():
	"""
	Hace la carga inicial del proceso

	Parameters
	----------

	Returns
	-------
	
	"""
	#Campos exta
	alertas = pd.read_csv(archivoAlertas, sep=separadorAlertas, low_memory=False)
	cantidadCamposExtra=len(alertas.columns) - len(col_list)
	for i in range(cantidadCamposExtra):
		col_list.append( "campo_" + str(i) )

	# Indicadores, inicial vacío
	indicadores_atacantes = pd.DataFrame(columns=('Remoto', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	indicadores_hosts = pd.DataFrame(columns=('Local', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	indicadores_detalle = pd.DataFrame(columns=('Remoto', 'Local', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	# Registro general de alertas ya clasificadas, inicial vacío
	repositorioAlertasClasificadas = pd.DataFrame(columns=(col_list)) #'timestamp','SID','Etapa','Subetapa','tecnica1','tecnica2','tecnica3','Remoto','Local', 'Alerta'
	repositorioAlertasTotal = pd.DataFrame(columns=(col_list))
	# Carga inicial de clasificacion de reglas (DtypeWarning: Columns (3,5,6,7,8,9,10) have mixed types.)
	clasificacion = pd.read_csv(reglasClasificacion,encoding="UTF-8",sep=";", low_memory=False)
	lib.carga.crear_archivo_sid_sin_clasificar(col_list)
	lib.carga.eliminar_resultado_anterior()

	if servicio:
		while True:
			run(repositorioAlertasClasificadas, clasificacion, indicadores_atacantes, indicadores_hosts, indicadores_detalle, repositorioAlertasTotal, cantidadCamposExtra)
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
		run(repositorioAlertasClasificadas, clasificacion, indicadores_atacantes, indicadores_hosts, indicadores_detalle, repositorioAlertasTotal, cantidadCamposExtra)


def run(repositorioAlertasClasificadas, clasificacion, indicadores_atacantes, indicadores_hosts, indicadores_detalle, repositorioAlertasTotal, cantidadCamposExtra):
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
			alertaClasificada=lib.carga.clasifica(alerta, clasificacion, repositorioAlertasClasificadas, redLocal, cantidadCamposExtra)			
			##if ( incluirNoClasificadas ): #guardaremos todas, clasificadas y no clasificadas
			##	repositorioAlertasTotal.loc[len(repositorioAlertasTotal.index)] = [alertaClasificada["timestamp"].item(), alertaClasificada["SID"].item(), alertaClasificada["Etapa"].item(), alertaClasificada["Subetapa"].item(), alertaClasificada["tecnica1"].item(), alertaClasificada["tecnica2"].item(), alertaClasificada["tecnica3"].item(), alertaClasificada["Remoto"].item(), alertaClasificada["Local"].item(), alertaClasificada["Alerta"].item()]
			if ( 	not alertaClasificada is None and 
					len(alertaClasificada.index) > 0 and 
					not np.isnan(alertaClasificada["Etapa"].item()) ): # Se procesa solo si no viene vacía y está clasificada
				##repositorioAlertasClasificadas.append(alertaClasificada, ignore_index=True)
				## 'timestamp','SID','etapa','Subetapa','tecnica1','tecnica2','tecnica3','Remoto','Local'
				
				#repositorioAlertasClasificadas.loc[len(repositorioAlertasClasificadas.index)] = [
				##AlertaTMP = pd.DataFrame({ alertaClasificada["timestamp"].item(), 
				##	alertaClasificada["SID"].item(), 
				##	alertaClasificada["Etapa"].item(), 
				##	alertaClasificada["Subetapa"].item(), 
				##	alertaClasificada["tecnica1"].item(), 
				##	alertaClasificada["tecnica2"].item(), 
				##	alertaClasificada["tecnica3"].item(), 
				##	alertaClasificada["Remoto"].item(), 
				##	alertaClasificada["Local"].item(), 
				##	alertaClasificada["Alerta"].item()})#, index=[0])
				##for i in range(cantidadCamposExtra):
				##	AlertaTMP.insert( 10 + i, "campo_" + str(i), [alerta[ 10 + i]], True) 
				##repositorioAlertasClasificadas.loc[len(repositorioAlertasClasificadas.index)] = AlertaTMP
				
				#print("repositorioAlertasClasificadas")
				#print(repositorioAlertasClasificadas)
				#print("alertaClasificada")
				#print(alertaClasificada)
				#if ( repositorioAlertasClasificadas.empty ):
				#	print("insertando primera")
				#	repositorioAlertasClasificadas = alertaClasificada
				#else:
				#	print("insertando siguiente")
					##repositorioAlertasClasificadas.loc[len(repositorioAlertasClasificadas.index)] = alertaClasificada
					#repositorioAlertasClasificadas.loc[len(repositorioAlertasClasificadas)] = alertaClasificada
					#repositorioAlertasClasificadas = pd.concat(
					#	[repositorioAlertasClasificadas, pd.DataFrame([alertaClasificada])], 
					#	ignore_index=True)
				repositorioAlertasClasificadas = repositorioAlertasClasificadas._append(alertaClasificada,ignore_index=True)

				indicadores_atacantes, indicadores_hosts, indicadores_detalle = lib.procesa.generaIndicadores(alertaClasificada, indicadores_atacantes, indicadores_hosts, indicadores_detalle)
				if servicio: #Guarda avance, genera indicadores graficos x grupo para mostrar avance 
					contadorGrupo = contadorGrupo + 1
					if ( contadorGrupo > 2000 ):
						contadorGrupo = 0
						repositorioAlertasClasificadas.to_csv(carpetaSalida + "alertas_clasificadas.csv",encoding="UTF-8",sep=";", index=False)
						indicadores_atacantes.sort_values(['Etapa 1'], ascending=[False])
						indicadores_atacantes.to_csv(carpetaSalida + "indicadores_atacantes.csv",encoding="UTF-8",sep=";", index=False)	
						indicadores_hosts.sort_values(['Etapa 1'], ascending=[False])
						indicadores_hosts.to_csv(carpetaSalida + "indicadores_hosts.csv",encoding="UTF-8",sep=";", index=False)
						indicadores_detalle.sort_values(['Etapa 1'], ascending=[False])
						indicadores_detalle.to_csv(carpetaSalida + "indicadores_detalle.csv",encoding="UTF-8",sep=";", index=False)
						lib.procesa.generaGraficos( "indicadores_atacantes.csv", "indicadores_hosts.csv",  "indicadores_detalle.csv", "alertas_clasificadas.csv", carpetaSalida )
			#Fin Si (Se procesa solo si no viene vacía)
			#else:
			#	print("[" + alertaClasificada["Etapa"].item() + "]")
			if not servicio:
				bar1.next()
		# Fin FOR / ciclo terminado
		if not servicio:
			bar1.finish()
		# Proceso final de indicadores
		##if ( incluirNoClasificadas ):
		##	repositorioAlertasTotal.to_csv(carpetaSalida + "alertas_clasificadas_y_no_clasificadas.csv",encoding="UTF-8",sep=";", index=False)
		repositorioAlertasClasificadas.to_csv(carpetaSalida + "alertas_clasificadas.csv",encoding="UTF-8",sep=";", index=False)
		indicadores_atacantes.sort_values(['Etapa 1'], ascending=[False])
		indicadores_atacantes.to_csv(carpetaSalida + "indicadores_atacantes.csv",encoding="UTF-8",sep=";", index=False)	
		indicadores_hosts.sort_values(['Etapa 1'], ascending=[False])
		indicadores_hosts.to_csv(carpetaSalida + "indicadores_hosts.csv",encoding="UTF-8",sep=";", index=False)
		indicadores_detalle.sort_values(['Etapa 1'], ascending=[False])
		indicadores_detalle.to_csv(carpetaSalida + "indicadores_detalle.csv",encoding="UTF-8",sep=";", index=False)
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

	if ( indicadores_atacantes.empty and indicadores_hosts.empty and indicadores_detalle.empty):
		print("No hay alertas clasificadas CKC, no se pueden generar graficos")
	else:
		if not servicio:
			print("Generando graficos")
		lib.procesa.generaGraficos( "indicadores_atacantes.csv", "indicadores_hosts.csv",  "indicadores_detalle.csv", "alertas_clasificadas.csv", carpetaSalida )

	if ( incluirNoClasificadas):
		print("Se generan alertas no clasificadas")
	#""

	csv_files = [ carpetaSalida + "alertas_clasificadas.csv", carpetaSalida + archivo_sid_sin_clasificar]
	df_append = pd.DataFrame()
	for file in csv_files:
	            df_temp = pd.read_csv(file, encoding="UTF-8", sep=";", low_memory=False)
	            df_append = df_append._append(df_temp, ignore_index=True)
	df_append.to_csv(carpetaSalida + "alertas_total.csv",encoding="UTF-8",sep=";", index=False)


if __name__ == '__main__':
    start()
