#
# Funciones de carga y preprocesamiento
#

#################################################################
# Configuración

# Donde se guardan sid (Snort ID) de alertas que no tienen etapa, sirve para asignarles una etapa
#archivo_sid_sin_clasificar = "sid_sin_clasificar.csv"

#################################################################
# Software

import pandas as pd
import matplotlib.pyplot as plt


def generaIndicadores(alertaClasificada, indicadores_atacantes, indicadores_hosts, indicadores_detalle):
	"""
	Genera indicadores macro durante la ejecución del proceso

	Parameters
	----------
	alertaClasificada : Dataframe
		Panda Dataframe que contiene la alerta ya clasificada para generar indicadores
	indicadores_atacantes: Dataframe
		Indicadores de avance del ataque, conteo por atacante
	indicadores_hosts: Dataframe
		Indicadores de avance del ataque, conteo por host o victima
	indicadores_detalle: Dataframe
		Indicadores de avance del ataque, conteo cruzado a modo de detalle precalculado
	Returns
	-------
	indicadores_atacantes: Dataframe
		retorna indicadores de avance del ataque, conteo por atacante, considerando la nueva alerta
	indicadores_hosts: Dataframe
		retorna indicadores de avance del ataque, conteo por host o victima, considerando la nueva alerta
	indicadores_detalle: Dataframe
		retorna indicadores de avance del ataque, conteo cruzado a modo de detalle precalculado, considerando la nueva alerta	
	"""
	#indicadores_atacantes = pd.DataFrame(columns=('Remoto', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	#indicadores_hosts = pd.DataFrame(columns=('Local', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	#indicadores_detalle = pd.DataFrame(columns=('Remoto', 'Local', 'Etapa 1', 'Etapa 2', 'Etapa 3', 'Etapa 4'))
	#repositorioAlertasClasificadas = pd.DataFrame(columns=('timestamp','SID','Etapa','Subetapa','Remoto','Local'))
	#tipo_destino, dato necesario para procesamiento en siguiente etapa. codigos: 1 HOME_NET / 2 EXTERNAL_NET / 0 DESCONOCIDO
	
	# Busqueda x atacante
	resultado_indicadores_atacantes=indicadores_atacantes.query("Remoto == '" + str(alertaClasificada["Remoto"].item()) + "'" )
	if len(resultado_indicadores_atacantes.index)==0: # Si no existe -> creamos y agregamos
		indicadores_atacantes.loc[len(indicadores_atacantes.index)] = [alertaClasificada["Remoto"].item(), 0, 0, 0, 0] 
	
	resultado_indicadores_atacantes=indicadores_atacantes.query("Remoto == '" + str(alertaClasificada["Remoto"].item()) + "'" )
	indicadores_atacantes["Etapa " + str(alertaClasificada["Etapa"].item()) ][resultado_indicadores_atacantes.index] = resultado_indicadores_atacantes["Etapa " + str(alertaClasificada["Etapa"].item()) ][resultado_indicadores_atacantes.index] + 1

	# Busqueda x hosts
	resultado_indicadores_hosts=indicadores_hosts.query("Local == '" + str(alertaClasificada["Local"].item()) + "'")
	#		"' and Etapa == " + str(alertaClasificada["Etapa"].item()) )
	if len(resultado_indicadores_hosts.index)==0: # Si no existe -> creamos y agregamos
		indicadores_hosts.loc[len(indicadores_hosts.index)] = [alertaClasificada["Local"].item(), 0, 0, 0, 0] 
	
	resultado_indicadores_hosts=indicadores_hosts.query("Local == '" + str(alertaClasificada["Local"].item()) + "'") 
	indicadores_hosts["Etapa " + str(alertaClasificada["Etapa"].item()) ][resultado_indicadores_hosts.index] = indicadores_hosts["Etapa " + str(alertaClasificada["Etapa"].item()) ][resultado_indicadores_hosts.index] + 1

	# Busqueda cruzado (detalle)
	resultado_indicadores_detalle=indicadores_detalle.query(
		"Remoto == '" + str(alertaClasificada["Remoto"].item()) + "' and " + 
		"Local == '" + str(alertaClasificada["Local"].item()) + "'")
	if len(resultado_indicadores_detalle.index)==0: # Si no existe -> creamos y agregamos
		indicadores_detalle.loc[len(indicadores_detalle.index)] = [alertaClasificada["Remoto"].item(), alertaClasificada["Local"].item(), 0, 0, 0, 0] 

	resultado_indicadores_detalle=indicadores_detalle.query(
		"Remoto == '" + str(alertaClasificada["Remoto"].item()) + "' and " + 
		"Local == '" + str(alertaClasificada["Local"].item()) + "'")

	indicadores_detalle["Etapa " + str(alertaClasificada["Etapa"].item()) ][resultado_indicadores_detalle.index] = resultado_indicadores_detalle["Etapa " + str(alertaClasificada["Etapa"].item()) ][resultado_indicadores_detalle.index] + 1


	return(indicadores_atacantes, indicadores_hosts, indicadores_detalle)





def generaGraficos(archivo_atacantes, archivo_hosts, archivo_detalle, carpetaSalida):
	"""
	Genera graficos basados en los indicadores macro, carga desde archivos para evitar q
	ue el "index" del dataframe salga dibujado

	Parameters
	----------
	archivo_atacantes : string
		nombre del archivo que contiene el resumen por atacantes
	archivo_hosts: string
		nombre del archivo que contiene el resumen por host
	archivo_detalle: string
		nombre del archivo que contiene el resumen de cruce por atacantes y hosts
	carpetaSalida: string
		carpeta de salida, donde se encuentran los archivos y donde se dejarán las imagenes
	Returns
	-------

	"""
	indicadores_atacantes = pd.read_csv(carpetaSalida + archivo_atacantes,encoding="latin-1",sep=";", index_col=0)
	indicadores_hosts = pd.read_csv(carpetaSalida + archivo_hosts,encoding="latin-1",sep=";", index_col=0)
	indicadores_detalle = pd.read_csv(carpetaSalida + archivo_detalle,encoding="latin-1",sep=";", index_col=0)

	# Graficos por Atacante
	#    
	indicadores_atacantes.plot.barh(stacked = True, figsize=(10,8), fontsize=6, log=False, color=["#6ec7ff","#fedf8b","#f46c43","#d43d4f"])
	#plt.legend(loc="lower left",bbox_to_anchor=(0.8,0.95))   # ["#fedf8b","#fdad60","#f46c43","#d43d4f" / #3387bc
	plt.title('Ataques recibidos por atacante')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('Atacante')
	#plt.show()	 #os.path.join('test.png') # use format='svg' or 'pdf' for vectorial pictures
	plt.savefig(carpetaSalida + 'imagenResumenAtacante.svg', dpi=300, format='svg', bbox_inches='tight') 

	# escala logaritmica
	indicadores_atacantes.plot.barh(stacked = True, figsize=(10,8), fontsize=6, log=True, color=["#6ec7ff","#ffff5a","#fdad60","#d43d4f"])
	plt.title('Ataques recibidos por atacante (escala logaritmica)')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('Atacante')
	plt.savefig(carpetaSalida + 'imagenResumenAtacante_log.svg', dpi=300, format='svg', bbox_inches='tight') 

	# Graficos por Host
	#    
	indicadores_hosts.plot.barh(stacked = True, figsize=(10,8), fontsize=6, log=False, color=["#6ec7ff","#fedf8b","#f46c43","#d43d4f"])
	#plt.legend(loc="lower left",bbox_to_anchor=(0.8,0.95))   # ["#fedf8b","#fdad60","#f46c43","#d43d4f" / #3387bc
	plt.title('Ataques recibidos por host')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('hosts')
	#plt.show()	 #os.path.join('test.png') # use format='svg' or 'pdf' for vectorial pictures
	plt.savefig(carpetaSalida + 'imagenResumenHosts.svg', dpi=300, format='svg', bbox_inches='tight') 

	# escala logaritmica
	indicadores_hosts.plot.barh(stacked = True, figsize=(10,8), fontsize=6, log=True, color=["#6ec7ff","#ffff5a","#fdad60","#d43d4f"])
	plt.title('Ataques recibidos por host (escala logaritmica)')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('hosts')
	plt.savefig(carpetaSalida + 'imagenResumenHosts_log.svg', dpi=300, format='svg', bbox_inches='tight') 