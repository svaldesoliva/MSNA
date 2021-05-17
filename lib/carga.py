import pandas as pd
import pandas.api.types as ptypes
import numpy as np
import os
import math 

def separa(linea):
	# limpieza previa
	linea = linea.strip()
	linea = linea.strip('\n')
	linea = linea.strip('\t')
	linea = linea.strip('\r')
	# separación en campos
	fila = linea.split(",")
	return(fila)


def clasifica(alerta, clasificacion):
	# alerta_csv: timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,ethsrc,ethdst,ethlen,tcpflags,tcpseq,tcpack,tcpln,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq
	# https://github.com/threatstream/snort/blob/master/src/output-plugins/spo_csv.c
	#
	# clasificacion: SID, Etapa, Subetapa, Observaciones, archivo, alerta
	
	clasificacionAlerta=clasificacion.query("SID == " + alerta[2])

	#print(clasificacionAlerta)

	# Si alerta tiene etapa clasificada ("Etapa" es entero)
	#if ptypes.is_integer_dtype(clasificacionAlerta['Etapa']): #.dtype == np.int32: 
	#print("-----------")
	#print(clasificacionAlerta["Etapa"])
	if len(clasificacionAlerta.index) > 0 and not math.isnan(clasificacionAlerta['Etapa'] ):
		#print("no es NaN")
		etapa = clasificacionAlerta["Etapa"].astype('int32')
		#print(etapa, end="")
		if ( etapa is 1 or etapa is 2 or etapa is 3 or etapa is 4 ): # Etapas validas 1,2,3,4 - las otras son ignoradas
			if not ptypes.is_numeric_dtype(clasificacionAlerta["Subetapa"]):
				clasificacionAlerta["Subetapa"] = 0 # Si viene vacio, vale 0
			
			AlertaClasificada = pd.DataFrame({	'timestamp': alerta[0],
										'SID': alerta[2],
										'Etapa': etapa,
										'Subetapa': clasificacionAlerta["Subetapa"].astype(np.int32),
										'Origen': alerta[6],
										'Destino': alerta[8]  })
			return(AlertaClasificada)
			#print(AlertaClasificada)
	else: #  Etapa no asignada -> Registramos los SID de alertas encontradas para futura clasificación
		#print("Etapa no es int32")
		guarda_sid_sin_clasificar(alerta[2])
	#print(AlertaClasificada)
#	largo=len(clasificacion)
#	for i in range(largo):
#		if clasificacion["SID"][i]==alerta[2]:
#	  		print("SID ----> " + clasificacion["SID"][i] + " <-- SID ")#+ " " + clasificacion[i][1]  + " " + clasificacion[i][2] + " " + clasificacion[i][3] + " " + clasificacion[i][4] + " " + clasificacion[i][5]) #outputs 'foo' then 'bar'

	#for row in clasificacion:
	#	for element in row:
	#		if element == alerta[2]:
	#			print(element)

	return()


def guarda_sid_sin_clasificar(sid):
	path = "sid_sin_clasificar.csv"

	if not os.path.exists(path): # Creamos archivo vacío
		archivo_guardar = open( path ,"w")
		fila_para_escribir = "SID\n"
		archivo_guardar.write(fila_para_escribir)
		archivo_guardar.close()

	sid_nc = pd.read_csv(path,encoding="latin-1",sep=";")
	mdata = sid_nc.query("SID == " + sid)
	if len(mdata.index) == 0: # Solo si SID no estaba antes
		print(sid)
		nueva_nc = pd.DataFrame({	'SID': sid }, index=[0])
		sid_nc = sid_nc.append(nueva_nc, ignore_index=True)
		sid_nc.to_csv(path, index=False)
	
	return()