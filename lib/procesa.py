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
	#indicadores_atacantes = pd.DataFrame(columns=('Remoto', 'Etapa', 'contador'))
	#indicadores_hosts = pd.DataFrame(columns=('Local', 'Etapa', 'contador'))
	#indicadores_detalle = pd.DataFrame(columns=('Remoto', 'Local', 'Etapa', 'contador'))
	#repositorioAlertasClasificadas = pd.DataFrame(columns=('timestamp','SID','Etapa','Subetapa','Remoto','Local'))
	#tipo_destino, dato necesario para procesamiento en siguiente etapa. codigos: 1 HOME_NET / 2 EXTERNAL_NET / 0 DESCONOCIDO
	
	# Busqueda 
	resultado_indicadores_atacantes=indicadores_atacantes.query("Remoto == '" + str(alertaClasificada["Remoto"].item()) + 
			"' and Etapa == " + str(alertaClasificada["Etapa"].item()) )
	if len(resultado_indicadores_atacantes.index)==0: # Si no existe -> creamos y agregamos
		#indicadores_atacantes_add = {	'Remoto': alertaClasificada["Remoto"].item(),
		#								'Etapa': alertaClasificada["Etapa"].item(),
		#								'contador':1 }	
		#indicadores_atacantes.append(indicadores_atacantes_add, ignore_index=True)
		indicadores_atacantes.loc[len(indicadores_atacantes.index)] = [alertaClasificada["Remoto"].item(), alertaClasificada["Etapa"].item(), 1] 
	else: # Ya existía, aumentamos 1 el contador
		indicadores_atacantes["contador"][resultado_indicadores_atacantes.index] = resultado_indicadores_atacantes["contador"].item() + 1

	# Busqueda 
	resultado_indicadores_hosts=indicadores_hosts.query("Local == '" + str(alertaClasificada["Local"].item()) + 
			"' and Etapa == " + str(alertaClasificada["Etapa"].item()) )
	if len(resultado_indicadores_hosts.index)==0: # Si no existe -> creamos y agregamos
		indicadores_hosts.loc[len(indicadores_hosts.index)] = [alertaClasificada["Local"].item(), alertaClasificada["Etapa"].item(), 1] 
	else: # Ya existía, aumentamos 1 el contador
		indicadores_hosts["contador"][resultado_indicadores_hosts.index] = resultado_indicadores_hosts["contador"].item() + 1

	# Busqueda 
	resultado_indicadores_detalle=indicadores_detalle.query(
		"Remoto == '" + str(alertaClasificada["Remoto"].item()) + "' and " + 
		"Etapa == " + str(alertaClasificada["Etapa"].item()) + " and " +
		"Local == '" + str(alertaClasificada["Local"].item()) + "'")
	if len(resultado_indicadores_detalle.index)==0: # Si no existe -> creamos y agregamos
		indicadores_detalle.loc[len(indicadores_detalle.index)] = [alertaClasificada["Remoto"].item(), alertaClasificada["Local"].item(), alertaClasificada["Etapa"].item(), 1] 
	else: # Ya existía, aumentamos 1 el contador
		indicadores_detalle["contador"][resultado_indicadores_detalle.index] = resultado_indicadores_detalle["contador"].item() + 1

		#print(indicadores_detalle)

	return(indicadores_atacantes, indicadores_hosts, indicadores_detalle)