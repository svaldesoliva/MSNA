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
	indicadores_detalle = pd.read_csv(carpetaSalida + archivo_detalle,encoding="latin-1",sep=";")

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

	"""
	fig = plt.figure(figsize=(8, 12))
	ax = fig.add_subplot(1, 1, 1, xticks=[], yticks=[],
	                     title="Statistics from the 2nd edition of\nfrom Audio Signal Processing for Music Applications by Stanford University\nand Universitat Pompeu Fabra of Barcelona on Coursera (Jan. 2016)")
	learners = [14460, 9720, 7047, 3059, 2149, 351]
	labels = ["Total learners joined", "Learners that visited the course", "Learners that watched a lecture",
	         "Learners that browsed the forums", "Learners that submitted an exercise", 
	          "Learners that obtained a grade >70%\n(got a Statement of Accomplishment)"]
	colors = ["#FF0000", "#FF4000", "#FF8000", "#FFBF00", "#FFFF00"]

	sankey = Sankey(ax=ax, scale=0.0015, offset=0.3)
	# Paso 1 (prior=0)
	sankey.add(flows=[1, -1],
	       labels=['input', 'output'])

	# Paso 2 (prior=1)
	sankey.add(flows=[1, -1],
	          labels=['input2', 'output2'],
	          prior=0,
	          connect=(1, 0))

	# Paso 3 (prior=2)
	sankey.add(flows=[1, -1],
	          labels=['input2', 'output2'],
	          prior=1,
	          connect=(1, 0))

	# Paso 4 (prior=3)
	sankey.add(flows=[1, -1],
	          labels=['input2', 'Final'],
	          prior=2,
	          connect=(1, 0))

	sankey.finish()
	plt.savefig(carpetaSalida + 'imagenPasos.svg', dpi=300, format='svg', bbox_inches='tight')

	"""
	"""
	# https://flothesof.github.io/sankey-tutorial-matplotlib.html
	fig = plt.figure(figsize=(12, 8))
	ax = fig.add_subplot(1, 1, 1, xticks=[], yticks=[],
	                     title="Test")
	learners = [17, 104, 232, 2]
	labels = ["Etapa 1", "Etapa 2", "Etapa 3", "Etapa 4"]
	colors = ["#6ec7ff","#ffff5a","#fdad60","#d43d4f"]

	sankey = Sankey(ax=ax)#, scale=0.0015, offset=0.3)
	for input_learner, output_learner, label, prior, color in zip(learners[:-1], learners[1:], 
	                                                              labels, [None, 0, 1, 2],
	                                                             colors):
	    if prior != 2:
	        sankey.add(flows=[input_learner, -output_learner, output_learner - input_learner],
					orientations=[0, 0, 1],
					patchlabel=label,
					labels=['', None, 'otro'],
					prior=prior,
					connect=(1, 0),
					pathlengths=[0, 0, 2],
					trunklength=10.,
					rotation=0,
					facecolor=color)
	    else:
	        sankey.add(flows=[input_learner, -output_learner, output_learner - input_learner],
					orientations=[0, 0, 1],
					patchlabel=label,
					labels=['', labels[-1], 'otro'],
					prior=prior,
					connect=(1, 0),
					pathlengths=[0, 0, 10],
					trunklength=10.,
					rotation=0,
					facecolor=color)
	diagrams = sankey.finish()
	for diagram in diagrams:
	    diagram.text.set_fontweight('bold')
	    diagram.text.set_fontsize('10')
	    for text in diagram.texts:
	        text.set_fontsize('10')
	ylim = plt.ylim()
	plt.ylim(ylim[0]*1.05, ylim[1])

	plt.savefig(carpetaSalida + 'imagenPasos.svg', dpi=300, format='svg', bbox_inches='tight')
	"""

	largo=len(indicadores_detalle)
	df_detalle = pd.DataFrame(columns=('Remoto','Etapa','Local','Contador'))
	for i in range(largo): 
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 1", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 1"]]
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 2", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 2"]]
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 3", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 3"]]
		df_detalle.loc[len(df_detalle.index)] = [indicadores_detalle.loc[i,"Remoto"], "Etapa 4", indicadores_detalle.loc[i,"Local"], indicadores_detalle.loc[i,"Etapa 4"]]


	fig = genSankey(df_detalle,cat_cols=['Remoto','Etapa','Local'],value_cols='Contador',title='Grafico')
	#plotly.offline.plot(fig, validate=False)
	plotly.offline.plot(fig, filename=carpetaSalida + 'detalle_interactivo.html')


	"""
	pip3 install plotly
	"""










def genSankey(df,cat_cols=[],value_cols='',title='Sankey Diagram'):
    """
    Función obtenida desde https://medium.com/kenlok/how-to-create-sankey-diagrams-from-dataframes-in-python-e221c1b4d6b0
    """
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