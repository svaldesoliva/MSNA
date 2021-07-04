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
#from matplotlib.sankey import Sankey
import plotly

import numpy as np
#from datetime import datetime
#import matplotlib.dates as mdates
import math


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





def generaGraficos(archivo_atacantes, archivo_hosts, archivo_detalle, archivo_clasificadas, carpetaSalida):
	"""
	Genera graficos basados en los indicadores macro, carga desde archivos para evitar
	que el "index" del dataframe salga dibujado

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
	alertas_clasificadas = pd.read_csv(carpetaSalida + archivo_clasificadas,encoding="latin-1",sep=";")
	

	#proporcion 8 alto por 11 atacantes, minimo 5
	alto_hosts=math.trunc( 8 * len(indicadores_hosts.index) / 11)
	if ( alto_hosts < 2 ):
		alto_hosts = 2

	alto_atacantes=math.trunc( 8 * len(indicadores_atacantes.index) / 11)
	if ( alto_atacantes < 2 ):
		alto_atacantes = 2

	#
	# Graficos por Atacante
	#    
	indicadores_atacantes.plot.barh(stacked = True, figsize=(10,alto_atacantes), fontsize=6, log=False, color=["#6ec7ff","#fedf8b","#f46c43","#d43d4f"])
	#plt.legend(loc="lower left",bbox_to_anchor=(0.8,0.95))   # ["#fedf8b","#fdad60","#f46c43","#d43d4f" / #3387bc
	plt.title('Ataques enviados por Host')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('Atacante')
	#plt.show()	 #os.path.join('test.png') # use format='svg' or 'pdf' for vectorial pictures
	plt.savefig(carpetaSalida + 'imagenResumenAtacante.svg', dpi=300, format='svg', bbox_inches='tight') 
	plt.close()


	# escala logaritmica
	indicadores_atacantes.plot.barh(stacked = True, figsize=(10,alto_atacantes), fontsize=6, log=True, color=["#6ec7ff","#fedf8b","#f46c43","#d43d4f"])
	plt.title('Ataques enviados por Host (escala logaritmica)')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('Atacante')
	plt.savefig(carpetaSalida + 'imagenResumenAtacante_log.svg', dpi=300, format='svg', bbox_inches='tight') 
	plt.close()

	indicadores_atacantes=pd.DataFrame() # Vaciamos el dataframe

	#
	# Graficos por Host
	#    
	indicadores_hosts.plot.barh(stacked = True, figsize=(10,alto_hosts), fontsize=6, log=False, color=["#6ec7ff","#fedf8b","#f46c43","#d43d4f"])
	#plt.legend(loc="lower left",bbox_to_anchor=(0.8,0.95))   # ["#fedf8b","#fdad60","#f46c43","#d43d4f" / #3387bc
	plt.title('Ataques recibidos por host')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('hosts')
	#plt.show()	 #os.path.join('test.png') # use format='svg' or 'pdf' for vectorial pictures
	plt.savefig(carpetaSalida + 'imagenResumenHosts.svg', dpi=300, format='svg', bbox_inches='tight') 
	plt.close()

	# escala logaritmica
	indicadores_hosts.plot.barh(stacked = True, figsize=(10,alto_hosts), fontsize=6, log=True, color=["#6ec7ff","#fedf8b","#f46c43","#d43d4f"])
	plt.title('Ataques recibidos por host (escala logaritmica)')
	plt.xlabel('Cantidad de ataques')
	plt.ylabel('hosts')
	plt.savefig(carpetaSalida + 'imagenResumenHosts_log.svg', dpi=300, format='svg', bbox_inches='tight')
	plt.close()

	indicadores_hosts=pd.DataFrame() # Vaciamos el dataframe

	#
	# Indicadores detalle
	#
	
	indicadores_detalle = pd.read_csv(carpetaSalida + archivo_detalle,encoding="latin-1",sep=";")
	largo=len(indicadores_detalle)
	df_detalle = pd.DataFrame(columns=('Remoto','Etapa','Local','Contador'))
	for i in range(largo): 
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 1", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 1"]]
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 2", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 2"]]
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 3", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 3"]]
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 4", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 4"]]


	fig = genSankey(df_detalle,cat_cols=['Remoto','Etapa','Local'],value_cols='Contador',title='Grafico')
	plotly.offline.plot(fig, filename=carpetaSalida + 'detalle_interactivo.html')
	#plot_mpl(fig, image='png', filename=carpetaSalida + 'detalle_interactivo.png')
	

	#
	# Avance en los cambios de etapa
	#
	
	#alertas_etapa4=alertas_clasificadas.query("Etapa == 4").groupby('Remoto').agg( {"Remoto":"count"}).rename(columns={'Remoto': 'Total'})
	alertas_interes0=alertas_clasificadas.groupby('Remoto').agg( {"Remoto":"count"}).rename(columns={'Remoto': 'Total'})
	#por problemas de memoria nos centramos en graficos mas interesantes
	alertas_etapa4=alertas_interes0.query("Total > 5") #no muy ambiciooso mas de 5 alertas
	alertas_etapa4 = alertas_etapa4.reset_index()
	#print(alertas_etapa4)
	alertas_interes0=pd.DataFrame() # Vaciamos el dataframe con el resultado intermedio, ahorro de RAM

	for index, row in alertas_etapa4.iterrows():

		alertas_interes1=alertas_clasificadas.query("Remoto == '" + str(row['Remoto']) + "'")

		alertas_local = alertas_interes1.groupby('Local').agg( {"Local":"count"}).rename(columns={'Local': 'Total'})
		alertas_local = alertas_local.reset_index()

		for index3, row3 in alertas_local.iterrows():

			alertas_interes=alertas_clasificadas.query("Remoto == '" + str(row['Remoto']) + "' and Local == '" + str(row3['Local']) + "'")

			#print("alertas_interes")
			#print(alertas_interes)

			cantidad = [] 
			fechahora = []
			etapas = []
			contadormaximo = 0
			etapa = -1 #inicial
			nombres = []
			cuantas_etapas = 0
			for index2, row2 in alertas_interes.iterrows():
				if ( etapa == -1 or etapa != row2['Etapa']): #Inicial o cambio de etapa, a reiniciar variables
					if ( etapa != -1 ): # Es cambio de etapa, hacemos el registro
						cantidad.append(contador)
						nombres.append(str(contador) + ' (Etapa ' + str(etapa) + ')')
						fechahora.append(inicio)
						if (etapa == 1): 
							etapas.append([110/255, 199/255, 255/255]) #6ec7ff - celeste
						if (etapa == 2):
							etapas.append([254/255, 223/255, 139/255]) #fedf8b - amarillo
						if (etapa == 3):
							etapas.append([244/255, 108/255, 67/255]) #f46c43 - naranja
						if (etapa == 4):
							etapas.append([200/255, 30/255, 30/255]) #d43d4f - rojo

						if ( contador > contadormaximo ):
							contadormaximo = contador
					etapa = row2['Etapa'] #nueva etapa
					contador = 1 # actual alerta
					inicio = row2['timestamp'] #row2['timestamp'].split(".",1)[0] #momento del cambio de estado
					cuantas_etapas = cuantas_etapas + 1
				else: #comun, seguimos en la misma etapa
					contador = contador + 1 #conteo dentro de la misma etapa

			# Última etapa, hacemos el registro
			cantidad.append(contador)
			nombres.append(str(contador) + ' (Etapa ' + str(etapa) + ')')
			fechahora.append(inicio)
			if (etapa == 1): 
				etapas.append([110/255, 199/255, 255/255]) #6ec7ff - celeste
			if (etapa == 2):
				etapas.append([254/255, 223/255, 139/255]) #fedf8b - amarillo
			if (etapa == 3):
				etapas.append([244/255, 108/255, 67/255]) #f46c43 - naranja
			if (etapa == 4):
				etapas.append([200/255, 30/255, 30/255]) #d43d4f - rojo  // 212/255, 61/255, 79/255

			if ( contador > contadormaximo ):
				contadormaximo = contador

			niveles = []
			signo = -1
			for v in cantidad:
				signo = -1 * signo
				niveles.append(signo * 0.05 * v / contadormaximo )

			if ( cuantas_etapas > 1 ): # Solo si tiene mas de una etapa
				# Con y sin etiquetas (sin etiqueta es util si hay muchas etapas)
				generaTimeLine(niveles, nombres, fechahora, etapas, str(row['Remoto'] + " a " + row3['Local']), carpetaSalida, str(row3['Total']), True )
				generaTimeLine(niveles, nombres, fechahora, etapas, str(row['Remoto'] + " a " + row3['Local']), carpetaSalida, str(row3['Total']), False )
		
			alertas_interes=pd.DataFrame() # Vaciamos el dataframe con el resultado intermedio




def generaTimeLine(levels, names, dates, colores, atacante, carpetaSalida, total_alertas, usarEtiquetas=False ):
	"""
	Genera graficos tipo timeline de un solo atacante separado del resto.
	https://matplotlib.org/stable/gallery/lines_bars_and_markers/timeline.html#sphx-glr-gallery-lines-bars-and-markers-timeline-py

	Parameters
	----------
	levels: array
		nivel o largo de cada barra, propocional al numero de ataques que corresponda, y corregido 
		para que el maximo numero de la barra mas larga
	names: array
		nombre de cada evento, acá se usa la cantidad
	dates: array
		fechas
	colores: array
		color segun etapas
	atacante: array
		dirección ip del atacante
	carpetaSalida: string
		carpeta de salida, donde se encuentran los archivos y donde se dejarán las imagenes
	usarEtiquetas: bool
		Dibujar o no etiquetas
	Returns
	-------

	"""

	# Create figure and plot a stem plot with the date
	fig, ax = plt.subplots(figsize=(18,8), constrained_layout=True)
	ax.set(title="Línea de tiempo para ataques de " + atacante)

	#ax.vlines(dates, 0, levels, color="tab:red")  # The vertical stems.

	ax.vlines(dates, 0, levels, color=colores)
	if (usarEtiquetas):
		ax.plot(dates, np.zeros_like(dates), "-o",
		        color="k", markerfacecolor="w")  # Baseline and markers on it.
	else:
		ax.plot(dates, np.zeros_like(dates), "-",
	        	color="k", markerfacecolor="w")  # Baseline and markers on it.

	# annotate lines
	if (usarEtiquetas):
		for d, l, r in zip(dates, levels, names):
			ax.annotate(r, xy=(d, l),
								xytext=(-3, np.sign(l)*3), textcoords="offset points",
								horizontalalignment="right",
								verticalalignment="bottom" if l > 0 else "top")

		plt.setp(ax.get_xticklabels(), rotation=90, ha="right")

	# remove y axis and spines
	ax.yaxis.set_visible(False)
	#sax.spines[["left", "top", "right"]].set_visible(False) #da error en algunas implementaciones
	ax.spines['top'].set_visible(False)
	ax.spines['right'].set_visible(False)
	ax.spines['left'].set_visible(False)

	ax.margins(y=0.1)
	#plt.show()
	file_atacante = atacante.replace(":", "-")
	if (usarEtiquetas):
		txt="_ce" # con etiquetas
	else:
		txt="_se"
	plt.savefig(carpetaSalida + 'time_line_atacante_' + total_alertas + "_" + file_atacante + txt + '.svg', dpi=300, format='svg', bbox_inches='tight')
	#plt.savefig(carpetaSalida + 'time_line_atacante_' + file_atacante + '.png', dpi=300, format='png', bbox_inches='tight')
	plt.close()



#
#
#  Para dibujar bien requiere datos filtrados
#
#
def genSankey(df,cat_cols=[],value_cols='',title='Sankey Diagram'):
    #
    #  Función obtenida desde https://medium.com/kenlok/how-to-create-sankey-diagrams-from-dataframes-in-python-e221c1b4d6b0
    #
    # maximum of 6 value cols -> 6 colors /  ['#4B8BBE','#306998','#FFE873','#FFD43B','#646464']
    colorPalette = ['#6ec7ff','#ffff5a','#fdad60','#d43d4f','#4B8BBE']
    labelList = []
    colorNumList = []
    for catCol in cat_cols:
        labelListTemp =  list(set(df[catCol].values))
        colorNumList.append(len(labelListTemp))
        labelList = labelList + labelListTemp
        
    # remove duplicates from labelList
    labelList = list(dict.fromkeys(labelList))
    
    # define colors based on number of levels
    colorList = []
    for idx, colorNum in enumerate(colorNumList):
        colorList = colorList + [colorPalette[idx]]*colorNum
        
    # transform df into a source-target pair
    for i in range(len(cat_cols)-1):
        if i==0:
            sourceTargetDf = df[[cat_cols[i],cat_cols[i+1],value_cols]]
            sourceTargetDf.columns = ['source','target','count']
        else:
            tempDf = df[[cat_cols[i],cat_cols[i+1],value_cols]]
            tempDf.columns = ['source','target','count']
            sourceTargetDf = pd.concat([sourceTargetDf,tempDf])
        sourceTargetDf = sourceTargetDf.groupby(['source','target']).agg({'count':'sum'}).reset_index()
        
    # add index for source-target pair
    sourceTargetDf['sourceID'] = sourceTargetDf['source'].apply(lambda x: labelList.index(x))
    sourceTargetDf['targetID'] = sourceTargetDf['target'].apply(lambda x: labelList.index(x))
    
    # creating the sankey diagram
    data = dict(
        type='sankey',
        node = dict(
          pad = 15,
          thickness = 20,
          line = dict(
            color = "black",
            width = 0.5
          ),
          label = labelList,
          color = colorList
        ),
        link = dict(
          source = sourceTargetDf['sourceID'],
          target = sourceTargetDf['targetID'],
          value = sourceTargetDf['count']
        )
      )
    
    layout =  dict(
        title = title,
        font = dict(
          size = 10
        )
    )
       
    fig = dict(data=[data], layout=layout)
    return fig

