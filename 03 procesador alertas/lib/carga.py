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
from netaddr import IPNetwork, IPAddress

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


def clasifica(alerta, clasificacion, repositorioAlertasClasificadas, redLocal):
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
	if (len(clasificacionAlerta.index) >0 and not math.isnan(clasificacionAlerta['Etapa']) and clasificacionAlerta['Etapa'].item()!=0):

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
										'Remoto': remoto,
										'Local': local,
										'Alerta': clasificacionAlerta["alerta"].item() # alerta[4] tiene menos informacion (solo msg)
									}, index=[0])
			return(AlertaClasificada)
	else: 
		guarda_sid_sin_clasificar(alerta[2])
	return(None)


def guarda_sid_sin_clasificar(sid):
	"""
	Si la etapa del tipo de alerta no está asignada se registra su Snort ID (SID)
	para futura clasificación, si ya está registrada se suma en uno su ocurrencia
	esto revelará su importancia

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
		nueva_nc = pd.DataFrame({	'SID': sid , 'Cantidad': 1}, index=[0])
		sid_nc = sid_nc.append(nueva_nc, ignore_index=True)
	else:
		sid_nc.loc[mdata.index, "Cantidad"] = sid_nc.loc[mdata.index, "Cantidad"] + 1
	sid_nc.to_csv(archivo_sid_sin_clasificar, index=False,encoding="latin-1",sep=";")	
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
		fila_para_escribir = "SID;Cantidad\n"
		archivo_guardar.write(fila_para_escribir)
		archivo_guardar.close()
	return()