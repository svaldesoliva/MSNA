# Procesador de Alertas Snort

## 01 genera template de reglas clasificacion
Genera un archivo vacío de clasificación, basado en las reglas de Snort, para iniciar la clasificación

## 02 extraer alertas
Lee un directorio con los dataset y extrae un archivo de alertas (en CSV) por cada archivo de trama de red (PCAP)

## 03 procesador alertas
Software que procesa las alertas Snort en CSV (01), con el archivo clasificación (02) ya editado

## 04 docs
Alguna documentación, o software que ayuda a generarla

### grafica
Genera grafico de distribución Scatter de las alertas clasificadas
