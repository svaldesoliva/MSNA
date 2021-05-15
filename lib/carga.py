import pandas as pd


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


	#matriz_de_datos.append(fila)
	print(alerta[2] + " " + alerta[6] )
	#print(clasificacion[alerta[2]]) 


	#for row in clasificacion:
	#	for element in row:
	#		if element == alerta[2]:
	#			print(element)

	return(alerta)