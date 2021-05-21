#!/bin/bash

#
# Extrae las reglas de cada archivo
# Manuel Cano - manuelcanoo@gmail.com
#

SALIDA="../clasificacion_base.csv"

#tipo de salto de linea
TSL=$'\n'
cd rules
rm -f $SALIDA
echo "SID;Etapa;Subetapa;Observaciones;tipo_destino;archivo;alerta" > $SALIDA
for f in *.rules ; do
	echo -n "Procesando: $f"
	#listado de alerta de in archivo, ie filas que no sean comentarios
	ALERTAS_ARCHIVO=`grep 'alert' $f|grep -v '# alert'|grep 'sid:'`
	#lectura linea a linea dentro de la variable, un "for" separaba por espacios
	COUNTER=0
	while TSL= read -r ALERTA; do
		let COUNTER=COUNTER+1
		echo -n "."
		SID=`echo -E $ALERTA|sed 's/\;/\n/g'|grep 'sid:'|cut -d ':' -f 2`
		ALERTA_SEGURA=`echo -E $ALERTA|sed 's/\;/,/g'|sed 's/\n/,/g'|sed 's/\r/,/g'`
		DESTINO=`echo $ALERTA_SEGURA|cut -d '>' -f 2|cut -d ' ' -f 2|cut -d '$' -f 2`
		DESTINO2=`echo $ALERTA_SEGURA|cut -d '>' -f 2|cut -d ' ' -f 2`
		CODIGODESTINO=0
		if [[ "$DESTINO" == "HOME_NET" ]] || [[ "$DESTINO" == "TELNET_SERVERS" ]] || [[ "$DESTINO" == "SMTP_SERVERS" ]] || [[ "$DESTINO" == "HTTP_SERVERS" ]] || [[ "$DESTINO" == "SQL_SERVERS" ]] || [[ "$DESTINO" == "any" ]]; then # si no es vacio
			CODIGODESTINO=1
		fi
		if [[ "$DESTINO" == "EXTERNAL_NET" ]] ; then # si no es vacio
			CODIGODESTINO=2
		fi
		#echo "($DESTINO)($DESTINO2) ($CODIGODESTINO) - $SID - $ALERTA_SEGURA)"
		if [[ ! -z "$SID" ]] ; then # si no es vacio
			echo -E "$SID;;;;$CODIGODESTINO;$f;$ALERTA_SEGURA" >> $SALIDA
		fi
	done <<< "$ALERTAS_ARCHIVO"
	echo " [$COUNTER reglas]"
done

