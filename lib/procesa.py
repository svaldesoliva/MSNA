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
	#indicadores_atacantes = pd.DataFrame(columns=('Origen', 'Etapa', 'contador'))
	#indicadores_hosts = pd.DataFrame(columns=('Destino', 'Etapa', 'contador'))
	#indicadores_detalle = pd.DataFrame(columns=('Origen', 'Destino', 'Etapa', 'contador'))
	#repositorioAlertasClasificadas = pd.DataFrame(columns=('timestamp','SID','Etapa','Subetapa','Origen','Destino'))

	# Busqueda 
	resultado_indicadores_atacantes=indicadores_atacantes.query("Origen == '" + str(alertaClasificada["Origen"].item()) + 
			"' and Etapa == " + str(alertaClasificada["Etapa"].item()) )
	if len(resultado_indicadores_atacantes.index)==0: # Si no existe -> creamos y agregamos
		#indicadores_atacantes_add = {	'Origen': alertaClasificada["Origen"].item(),
		#								'Etapa': alertaClasificada["Etapa"].item(),
		#								'contador':1 }	
		#indicadores_atacantes.append(indicadores_atacantes_add, ignore_index=True)
		indicadores_atacantes.loc[len(indicadores_atacantes.index)] = [alertaClasificada["Origen"].item(), alertaClasificada["Etapa"].item(), 1] 
	else: # Ya existía, aumentamos 1 el contador
		indicadores_atacantes["contador"][resultado_indicadores_atacantes.index] = resultado_indicadores_atacantes["contador"].item() + 1

	# Busqueda 
	resultado_indicadores_hosts=indicadores_hosts.query("Destino == '" + str(alertaClasificada["Destino"].item()) + 
			"' and Etapa == " + str(alertaClasificada["Etapa"].item()) )
	if len(resultado_indicadores_hosts.index)==0: # Si no existe -> creamos y agregamos
		indicadores_hosts.loc[len(indicadores_hosts.index)] = [alertaClasificada["Destino"].item(), alertaClasificada["Etapa"].item(), 1] 
	else: # Ya existía, aumentamos 1 el contador
		indicadores_hosts["contador"][resultado_indicadores_hosts.index] = resultado_indicadores_hosts["contador"].item() + 1

	# Busqueda 
	resultado_indicadores_detalle=indicadores_detalle.query(
		"Origen == '" + str(alertaClasificada["Origen"].item()) + "' and " + 
		"Etapa == " + str(alertaClasificada["Etapa"].item()) + " and " +
		"Destino == '" + str(alertaClasificada["Destino"].item()) + "'")
	if len(resultado_indicadores_detalle.index)==0: # Si no existe -> creamos y agregamos
		indicadores_detalle.loc[len(indicadores_detalle.index)] = [alertaClasificada["Origen"].item(), alertaClasificada["Destino"].item(), alertaClasificada["Etapa"].item(), 1] 
	else: # Ya existía, aumentamos 1 el contador
		indicadores_detalle["contador"][resultado_indicadores_detalle.index] = resultado_indicadores_detalle["contador"].item() + 1

		print(indicadores_detalle)

	return(indicadores_atacantes, indicadores_hosts, indicadores_detalle)