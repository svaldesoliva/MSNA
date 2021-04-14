import pandas as pd


def separa(linea):
	linea = linea.strip()
	linea = linea.strip('\n')
	linea = linea.strip('\t')
	linea = linea.strip('\r')
	fila = linea.split(",")
	return(fila)

def clasifica(linea):
#    print(linea)
	linea = linea.strip()
	linea = linea.strip('\n')
	linea = linea.strip('\t')
	linea = linea.strip('\r')
	fila = linea.split(",")
	#matriz_de_datos.append(fila)
	#print(fila[5])
	return(fila)