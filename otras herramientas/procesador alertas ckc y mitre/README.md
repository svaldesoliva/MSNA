# Procesador de Alertas Snort v1.1

## Nuevo en v1.1
### Archivo de configuración
Con valores para sepadadores del CSV y otros parametros

### Técnicas Mitre
Campos con técnicas Mitre, solo para las alertas que tienen código Mitre 

### Alertas no clasificadas, clasificadas y total
Listado de alertas clasificadas, No clasificadas, y Total (suma de las dos anteriores) en CKC. 
Se separan debido a que solo las CKC pueden tener gráficos CKC.

### Columnas extra
Si "alert.csv" viene con campos extra, estos se copian a los archivos de salida


## Requisitos
### Python 3
Probado con Python 3.8.5

### pygtail
Obtenido desde https://pypi.org/project/pygtail/
instalación: pip install pygtail

### pandas
Homepage https://pandas.pydata.org/
instalación: pip install pandas

### progress
Homepage https://github.com/verigak/progress/
instalación: pip install progress

### matplotlib
Homepage https://matplotlib.org/
instalación: pip install matplotlib

### plotly
Homepage https://plotly.com/python/
instalación: pip3 install plotly

### numpy 
instalación: pip3 install numpy

### netaddr
instalación: pip3 install netaddr

## Operación
- Copiar archivo "alert.csv" con las alertas desde la salida de Snort
- Ejecutar: python procesador_alertas.py

<!---
## Notas adicionales
python-daemon - https://github.com/martinrusev/python-daemon/
-->
