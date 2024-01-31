#
# Funciones de carga y preprocesamiento
#

#incluye directorio padre
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#################################################################
# Configuración, importa variables desde "configuracion.py" en directorio padre
from configuracion import *

#################################################################
# Software
import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'

import pandas.api.types as ptypes
import numpy as np
import os
import math 
from netaddr import IPNetwork, IPAddress
from os import remove
import glob


def separa(linea):
	"""
	Recibe una linea, le quita posibles saltos de línea y otros catacteres problematicos, lo devielve como array. 

	Parameters
	----------
	linea : string
		linea de texto, con campos separados por ','
	Returns
	-------
	fila : array
		linea en formato array
	"""
	# limpieza previa
	linea = linea.strip()
	linea = linea.strip('\n')
	linea = linea.strip('\t')
	linea = linea.strip('\r')
	# separación en campos
	fila = linea.split(separadorAlertas)
	return(fila)


def clasifica(alerta, clasificacion, repositorioAlertasClasificadas, redLocal, cantidadDeCamposExtra):
	"""
	Recibe una alerta, y la clasifica segun tipo de alerta y etapa CKC. 

	Parameters
	----------
	alerta : array
		Alerta sin procesar en formato array, el formato es el siguiente:
		alerta_csv: timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,ethsrc,ethdst,ethlen,tcpflags,tcpseq,tcpack,tcpln,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq
		el cual está definido en: https://github.com/threatstream/snort/blob/master/src/output-plugins/spo_csv.c
	clasificacion : Dataframe
		Panda Dataframe que contiene los tipos de alerta definidos, que incluye el SID y la etapa de CKC correspondiente.
		campos del CSV de clasificacion: SID, Etapa, Subetapa, Observaciones, archivo, alerta 
	repositorioAlertasClasificadas: Dataframe
		Colección de alertas ya guardadas, aquí obtenemos la historia para reclasificar
	redLocal: string
		Red que consideraremos local
	Returns
	-------
	AlertaClasificada: Dataframe or None
		Panda Dataframe que contiene la alerta ya clasificada, None si no se puede clasificar
	"""

	# Busqueda en Panda Dataframe
	clasificacionAlerta=clasificacion.query("SID == " + alerta[2])

	# Busqueda existosa, y no viene vacío
	if (len(clasificacionAlerta.index) >0 and 
		# not math.isnan(clasificacionAlerta['Etapa']) and # future deprecated, se cambio por similar en numpy
		not np.isnan(clasificacionAlerta['Etapa']).bool() and 
		clasificacionAlerta['Etapa'].item()!=0):

		####clasificacionAlerta["Etapa"][clasificacionAlerta.index].astype('int32')
		etapa = int(clasificacionAlerta["Etapa"].item())
		if ( etapa > 0 and etapa < 5 ): # Etapas validas 1,2,3,4 - las otras son ignoradas
			#print(etapa, end="")  # Monitorear avance en desarrollo
			if not ptypes.is_numeric_dtype(clasificacionAlerta["Subetapa"]) or np.isnan(clasificacionAlerta['Subetapa']).bool() :
				subetapa = 0 # Si viene vacio, vale 0
			else:
				subetapa = int(clasificacionAlerta["Subetapa"].item())


			if ( clasificacionAlerta["tipo_destino"].item() == 2 ): # 2 -> origen = local / estino = remoto
				remoto = alerta[8]
				local = alerta[6]
			else: # 1 -> origen = local / estino = remoto  ///  
				remoto = alerta[6]
				local = alerta[8]
			"""
			# experimento de clasificacion de remoto/local. Inutil en contexto CTF en donde los nodos que se protejen tambiena atacan
			if ( IPAddress( alerta[6] ) in IPNetwork( redLocal )) and not ( IPAddress( alerta[8] ) in IPNetwork( redLocal )):
				remoto = alerta[8]
				local = alerta[6]
			else: # 1 -> origen = local / estino = remoto  ///  
				if not ( IPAddress( alerta[6] ) in IPNetwork( redLocal )) and ( IPAddress( alerta[8] ) in IPNetwork( redLocal )):
					remoto = alerta[6]
					local = alerta[8]
				else:
					if (alerta[8]=="::" or alerta[8]=="255.255.255.255" ): #broadcast alerta[8] sera local
						remoto = alerta[6]
						local = alerta[8]
					else:
						if (alerta[6]=="::" or alerta[6]=="255.255.255.255"): #broadcast alerta[6] sera local
							remoto = alerta[8]
							local = alerta[6]
						else:
							a=alerta[6].split(".")
							if (len(a)==4 and a[3]=="1"): #router
								remoto = alerta[6]
								local = alerta[8]
							else:
								remoto = alerta[8]
								local = alerta[6]
			"""
			# Excepciones que sacan provecho a la identificación del avance por etapa:

			# Si esta etapa es 2.1 (conexion existosa, sin problemas) y 
			# existió anteriormente un ataque (3.1) que de ser exitoso puede haber dado acceso  ==> etapa 4: server comprometido
			if ( etapa == 2 and subetapa == 1 ):
				resultado_ataques_previos1=repositorioAlertasClasificadas.query(
										"Remoto == '" + remoto + "' and " + 
										"Local == '" + local + "' and " +
										"Etapa == 3 and Subetapa == 1 " )
				if ( len(resultado_ataques_previos1.index) >0 ):
					etapa = 4
					subetapa = 10 # indicador de calculado

			# Si esta etapa es 2.1 (conexion existosa, sin problemas) y 
			# existieron anteriormente multiples un ataques tipo 3, que de ser exitoso puede haber dado acceso  ==> etapa 4: server comprometido
			if ( etapa == 2 and subetapa == 1 ):
				resultado_ataques_previos1=repositorioAlertasClasificadas.query(
										"Remoto == '" + remoto + "' and " + 
										"Local == '" + local + "' and " +
										"Etapa == 3  " )
				if ( len(resultado_ataques_previos1.index) > 4 ): # 5 o más no puede ser coincidencia
					etapa = 4
					subetapa = 11 # indicador de calculado


			AlertaClasificada = pd.DataFrame({	'timestamp': alerta[0],
										'SID': alerta[2],
										'Etapa': etapa,
										'Subetapa': subetapa,
										'tecnica1': clasificacionAlerta["tecnica1"].item(), #tecnica1,
										'tecnica2': clasificacionAlerta["tecnica2"].item(), #tecnica2,
										'tecnica3': clasificacionAlerta["tecnica3"].item(), #tecnica3,
										'Remoto': remoto,
										'Local': local,
										'Alerta': clasificacionAlerta["alerta"].item() # alerta[4] tiene menos informacion (solo msg)
									}, index=[0])
			for i in range(cantidadDeCamposExtra):
				AlertaClasificada.insert( 10 + i, "campo_" + str(i), [alerta[ 10 + i]], True) 

			return(AlertaClasificada)
	else: 
		#guarda_sid_sin_clasificar(alerta[2])
		if ( incluirNoClasificadas ):
			AlertaClasificada = pd.DataFrame({	'timestamp': alerta[0],
										'SID': alerta[2],
										'Etapa': '',
										'Subetapa': '',
										'tecnica1': '',
										'tecnica2': '',
										'tecnica3': '',
										'Remoto': alerta[6],
										'Local': alerta[8],
										'Alerta': '' # alerta[4] tiene menos informacion (solo msg)
									}, index=[0])
			for i in range(cantidadDeCamposExtra):
				AlertaClasificada.insert( 10 + i, "campo_" + str(i), [alerta[ 10 + i]], True) 
			guarda_sid_sin_clasificar(AlertaClasificada)
#	return(None)


def guarda_sid_sin_clasificar(anc):
	"""
	Si la etapa del tipo de alerta no está asignada se registra su Snort ID (SID)
	para futura clasificación, si ya está registrada se suma en uno su ocurrencia
	esto revelará su importancia

	Parameters
	----------
	anc : Alerta dataframe
		anc, alerta no clasificada
	Returns
	-------

	"""
	anc.to_csv(carpetaSalida + archivo_sid_sin_clasificar, mode='a', index=False, encoding="latin-1",sep=";", header=False)
	return()



def crear_archivo_sid_sin_clasificar(col_list):
	"""
	Verifica si existe, y si no existe crea, el archivo CSV para almacenar los SID no registrados

	Parameters
	----------

	Returns
	-------
	
	"""
	if os.path.exists(carpetaSalida + archivo_sid_sin_clasificar): # Borrar, lo creamos cada vez solo si lo necesitamos
		remove(carpetaSalida + archivo_sid_sin_clasificar)

	if ( incluirNoClasificadas and not os.path.exists(archivo_sid_sin_clasificar) ): # Creamos archivo vacío
		#archivo_guardar = open( carpetaSalida + archivo_sid_sin_clasificar ,"w")
		#fila_para_escribir = "timestamp;SID;Etapa;Subetapa;tecnica1;tecnica2;tecnica3;Remoto;Local;Alerta\n"
		#archivo_guardar.write(fila_para_escribir)
		#archivo_guardar.close()
		inicial = pd.DataFrame(columns=(col_list))
		inicial.to_csv(carpetaSalida + archivo_sid_sin_clasificar,encoding="UTF-8",sep=";", index=False)
	return()



def eliminar_resultado_anterior():
	if os.path.exists(carpetaSalida + "alertas_clasificadas.csv"): 
		remove(carpetaSalida + "alertas_clasificadas.csv")

	if os.path.exists(carpetaSalida + "detalle_interactivo.html"): 
		remove(carpetaSalida + "detalle_interactivo.html")

	if os.path.exists(carpetaSalida + "imagenResumenAtacante.svg"): 
		remove(carpetaSalida + "imagenResumenAtacante.svg")

	if os.path.exists(carpetaSalida + "imagenResumenAtacante_log.svg"): 
		remove(carpetaSalida + "imagenResumenAtacante_log.svg")

	if os.path.exists(carpetaSalida + "imagenResumenHosts.svg"):
		remove(carpetaSalida + "imagenResumenHosts.svg")

	if os.path.exists(carpetaSalida + "imagenResumenHosts_log.svg"): 
		remove(carpetaSalida + "imagenResumenHosts_log.svg")

	if os.path.exists(carpetaSalida + "indicadores_atacantes.csv"): 
		remove(carpetaSalida + "indicadores_atacantes.csv")

	if os.path.exists(carpetaSalida + "indicadores_detalle.csv"): 
		remove(carpetaSalida + "indicadores_detalle.csv")

	if os.path.exists(carpetaSalida + "indicadores_hosts.csv"):
		remove(carpetaSalida + "indicadores_hosts.csv")

	if os.path.exists(carpetaSalida + "alertas_total.csv"):
		remove(carpetaSalida + "alertas_total.csv")

	files = glob.glob(carpetaSalida + 'time_line_atacante_*.svg', recursive=True)

	for f in files:
	    try:
	        os.remove(f)
	    except OSError as e:
	        print("Error: %s : %s" % (f, e.strerror))
