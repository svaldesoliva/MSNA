#
# Funciones de carga y preprocesamiento
#

#################################################################
# Configuración

# Donde se guardan sid (Snort ID) de alertas que no tienen etapa, sirve para asignarles una etapa
archivo_sid_sin_clasificar = "sid_sin_clasificar.csv"

#################################################################
# Software
import pandas as pd
import pandas.api.types as ptypes
import numpy as np
import os
import math 

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
	fila = linea.split(",")
	return(fila)


def clasifica(alerta, clasificacion):
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
	Returns
	-------
	AlertaClasificada: Dataframe or None
		Panda Dataframe que contiene la alerta ya clasificada, None si no se puede clasificar
	"""

	# Busqueda en Panda Dataframe
	clasificacionAlerta=clasificacion.query("SID == " + alerta[2])

	# Busqueda existosa, y no viene vacío
	if len(clasificacionAlerta.index) >0 and not math.isnan(clasificacionAlerta['Etapa'] ):

		####clasificacionAlerta["Etapa"][clasificacionAlerta.index].astype('int32')
		etapa = int(clasificacionAlerta["Etapa"].item())
		if ( etapa > 0 and etapa < 5 ): # Etapas validas 1,2,3,4 - las otras son ignoradas
			#print(etapa, end="")  # Monitorear avance en desarrollo
			if not ptypes.is_numeric_dtype(clasificacionAlerta["Subetapa"]) or math.isnan(clasificacionAlerta['Subetapa']):
				subetapa = 0 # Si viene vacio, vale 0
			else:
				subetapa = int(clasificacionAlerta["Subetapa"].item())

			if ( clasificacionAlerta["tipo_destino"].item() == 2 ): # 2 -> origen = local / estino = remoto
				remoto = alerta[8]
				local = alerta[6]
			else: # 1 -> origen = local / estino = remoto  ///  
				remoto = alerta[6]
				local = alerta[8]
			AlertaClasificada = pd.DataFrame({	'timestamp': alerta[0],
										'SID': alerta[2],
										'Etapa': etapa,
										'Subetapa': subetapa,
										'Remoto': remoto,
										'Local': local  }, index=[0])
			return(AlertaClasificada)
	else: 
		guarda_sid_sin_clasificar(alerta[2])
	return(None)


def guarda_sid_sin_clasificar(sid):
	"""
	Si la etapa del tipo de alerta no está asignada se registra su Snort ID (SID)
	para futura clasificación

	Parameters
	----------
	sid : int
		Snort ID (SID), identificador unico por tipo de alerta
	Returns
	-------

	"""
	sid_nc = pd.read_csv(archivo_sid_sin_clasificar,encoding="latin-1",sep=";")
	mdata = sid_nc.query("SID == " + sid)
	if len(mdata.index) == 0: # Solo si SID no estaba antes
		#print(sid) # Monitoreo de avance durante desarrollo
		nueva_nc = pd.DataFrame({	'SID': sid }, index=[0])
		sid_nc = sid_nc.append(nueva_nc, ignore_index=True)
		sid_nc.to_csv(archivo_sid_sin_clasificar, index=False)	
	return()



def crear_archivo_sid_sin_clasificar():
	"""
	Verifica si existe, y si no existe crea, el archivo CSV para almacenar los SID no registrados

	Parameters
	----------

	Returns
	-------
	
	"""
	if not os.path.exists(archivo_sid_sin_clasificar): # Creamos archivo vacío
		archivo_guardar = open( archivo_sid_sin_clasificar ,"w")
		fila_para_escribir = "SID\n"
		archivo_guardar.write(fila_para_escribir)
		archivo_guardar.close()
	return()