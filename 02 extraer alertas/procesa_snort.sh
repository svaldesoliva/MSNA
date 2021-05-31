#!/bin/bash

#Nadie mas escribiendo en snort
service snort stop

#archivos borrados, no es necesario
#snort -c /etc/snort/snort.conf --pcap-dir=./ --pcap-reset

#procesamos todos los pcap de este directorio
for f in *.pcap; do
  echo "Procesando -> $f"
  DESTINO="${f%%.*}"
  #echo $DESTINO

  # No datos previos
  rm -f /var/log/snort/snort.log
  rm -f /var/log/snort/alert.csv

  snort -c /etc/snort/snort.conf  -r "$f" -q 

  mv /var/log/snort/snort.log "snort_$DESTINO.log"
  mv /var/log/snort/alert.csv "alert_$DESTINO.csv"

done


