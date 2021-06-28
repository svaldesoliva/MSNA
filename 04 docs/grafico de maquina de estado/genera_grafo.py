import numpy as np
import matplotlib.pyplot as plt 

import pandas as pd

# Import the MarkovChain class from markovchain.py
from lib.markovchain import MarkovChain

carpetaSalida = "salida/"

#Matriz vacía
P = np.array([
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0]
])
etapa_anterior=0 # es necesario usar un inicial que exista
alertas = pd.read_csv("alertas_clasificadas.csv",encoding="latin-1",sep=";") # Repo de datos!
print("Etapa: ", end="")
for i in alertas.index: 
	#print(str(i) + " Etapa: " + str(alertas["Etapa"][i]) )
	print(str(alertas["Etapa"][i]), end="")
	etapa = alertas["Etapa"][i]
	if (etapa_anterior == 0 ):
		etapa_anterior = etapa
	else:
		pos1 = etapa_anterior - 1 # 0 a 3
		pos2 = etapa - 1
		P[pos1, pos2] = P[pos1, pos2] + 1
		etapa_anterior = etapa
print(" ")
print(P)
mc = MarkovChain(P, ['E 1', 'E 2', 'E 3', 'E 4'])
#mc.draw()
mc.draw(carpetaSalida + "Maquina_estado-CKC.png")