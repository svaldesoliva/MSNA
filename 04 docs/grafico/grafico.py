#!/usr/bin/python -tt

import matplotlib.pyplot as plt
#Tamaño
plt.rcParams["figure.figsize"] = (18,3)

#malla
fig, ax = plt.subplots()
#number_of_runs = range(0,57)    # use your actual number_of_runs
#ax.set_xticks(number_of_runs, minor=False)
plt.grid(True, linestyle='--')
#ax.xaxis.grid(True, which='major')
#ax.yaxis.grid(True, which='major')
#ax.set_ylim([-1,4])
ax.set_ylim([-0.75,3.75])



#
# b11 -> bf
separador="CARACTER(34)&"
formula1 = "=\"[\"&"
for x in range(25):
      formula1 = formula1 + separador + "ESPACIOS(" + chr(66 + x) + "11)&" + separador + "\",\"&"
for x in range(26):
      formula1 = formula1 + separador + "ESPACIOS(A" + chr(65 + x) + "11)&" + separador + "\",\"&"
for x in range(5):
      formula1 = formula1 + separador + "ESPACIOS(B" + chr(65 + x) + "11)&" + separador + "\",\"&"
formula1 = formula1 + separador + "ESPACIOS(BF11)&" + separador + "\"]\""
print(formula1)
print("Formula excel para numeros")
separador=""
formula1 = "=\"[\"&"
for x in range(25):
      formula1 = formula1 + separador + "ESPACIOS(" + chr(66 + x) + "12)&" + separador + "\",\"&"
for x in range(26):
      formula1 = formula1 + separador + "ESPACIOS(A" + chr(65 + x) + "12)&" + separador + "\",\"&"
for x in range(5):
      formula1 = formula1 + separador + "ESPACIOS(B" + chr(65 + x) + "12)&" + separador + "\",\"&"
formula1 = formula1 + separador + "ESPACIOS(BF12)&" + separador + "\"]\""
print(formula1)

"""
#https://www.geeksforgeeks.org/matplotlib-pyplot-scatter-in-python/

# salida desde excel
["attack-responses.rules","backdoor.rules","bad-traffic.rules","community-deleted.rules","community-dos.rules","community-exploit.rules","community-game.rules","community-icmp.rules","community-imap.rules","community-misc.rules","community-nntp.rules","community-sip.rules","community-smtp.rules","community-sql-injection.rules","community-virus.rules","community-web-attacks.rules","community-web-cgi.rules","community-web-client.rules","community-web-iis.rules","community-web-misc.rules","community-web-php.rules","ddos.rules","deleted.rules","dns.rules","dos.rules","exploit.rules","finger.rules","ftp.rules","icmp.rules","icmp-info.rules","imap.rules","misc.rules","mysql.rules","netbios.rules","nntp.rules","oracle.rules","p2p.rules","policy.rules","pop2.rules","pop3.rules","rpc.rules","rservices.rules","scan.rules","shellcode.rules","smtp.rules","snmp.rules","sql.rules","telnet.rules","tftp.rules","virus.rules","web-attacks.rules","web-cgi.rules","web-client.rules","web-iis.rules","web-misc.rules","web-php.rules","x11.rules"]
[0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,2,0,0,0,0,0,22,93,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0]
[1,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5,3,0,0,8,0,0,13,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7,0,0,1,0,0,0]
[14,0,5,1,6,5,1,1,2,3,1,1,1,9,2,3,1,8,1,135,334,25,37,13,16,80,0,33,0,0,32,11,0,111,12,297,0,0,3,18,30,2,0,0,40,2,22,5,4,0,14,7,8,5,18,27,0]
[2,76,1,0,0,1,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,7,87,0,0,0,1,0,0,0,0,0,3,2,0,0,19,1,0,0,0,0,0,42,0,0,1,0,0,1,0,0,0,0,0,0,2]


v2
["attack-responses.rules","backdoor.rules","bad-traffic.rules","chat.rules","community-deleted.rules","community-dos.rules","community-exploit.rules","community-game.rules","community-icmp.rules","community-imap.rules","community-misc.rules","community-nntp.rules","community-sip.rules","community-smtp.rules","community-sql-injection.rules","community-virus.rules","community-web-attacks.rules","community-web-cgi.rules","community-web-client.rules","community-web-iis.rules","community-web-misc.rules","community-web-php.rules","ddos.rules","deleted.rules","dns.rules","dos.rules","exploit.rules","finger.rules","ftp.rules","icmp.rules","icmp-info.rules","imap.rules","info.rules","misc.rules","mysql.rules","netbios.rules","nntp.rules","oracle.rules","p2p.rules","policy.rules","pop2.rules","pop3.rules","rpc.rules","rservices.rules","scan.rules","shellcode.rules","smtp.rules","snmp.rules","sql.rules","telnet.rules","tftp.rules","virus.rules","web-attacks.rules","web-cgi.rules","web-client.rules","web-iis.rules","web-misc.rules"]
[0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,2,0,0,0,0,0,22,93,0,1,0,0,0,0,0,0,0,0,0,0,0,18,0,0,0,0,0,0,0,0,0,0,0,0]
[1,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5,3,0,0,8,0,0,13,0,0,0,0,5,0,0,4,0,1,0,1,0,0,1,0,0,0,0,1,0,0,0,0,9,27,1,1,4]
[14,0,5,0,1,6,5,1,1,2,3,1,1,1,9,2,3,1,8,1,135,334,25,37,13,16,80,0,33,0,0,32,0,11,3,112,12,297,0,0,3,18,31,2,0,0,40,3,22,5,4,0,15,7,8,5,18]
[2,76,1,1,0,0,1,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,7,87,0,0,0,1,0,0,0,0,0,1,0,2,0,0,19,1,0,0,0,0,0,42,0,0,1,0,0,1,0,1,0,0,0]


"""

#Paso 1
y1 = []
y2 = []
y3 = []
y4 = []
for x in range(57):
      y1.append("Etapa 1")
      y2.append("Etapa 2")
      y3.append("Etapa 3")
      y4.append("Etapa 4")


#x1 = ["p1","p1","p1"]
x1 = ["attack-responses","backdoor","bad-traffic","community-deleted","community-dos","community-exploit","community-game","community-icmp","community-imap","community-misc","community-nntp","community-sip","community-smtp","community-sql-injection","community-virus","community-web-attacks","community-web-cgi","community-web-client","community-web-iis","community-web-misc","community-web-php","ddos","deleted","dns","dos","exploit","finger","ftp","icmp","icmp-info","imap","misc","mysql","netbios","nntp","oracle","p2p","policy","pop2","pop3","rpc","rservices","scan","shellcode","smtp","snmp","sql","telnet","tftp","virus","web-attacks","web-cgi","web-client","web-iis","web-misc","web-php","x11"]
#s1 = [100, 100,100]
s1 = [0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,2,0,0,0,0,0,22,93,0,1,0,0,0,0,0,0,0,0,0,0,0,18,0,0,0,0,0,0,0,0,0,0,0,0]
#c1 = ["green", "yellow","orange"]
c1 = "orange" #"green"
m1 = "o" #"s"

#Paso 2
x2 = x1
s2 = [1,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5,3,0,0,8,0,0,13,0,0,0,0,5,0,0,4,0,1,0,1,0,0,1,0,0,0,0,1,0,0,0,0,9,27,1,1,4]
c2 = "orange" #"yellow"
m2 = "o" #"^"

#Paso 3
x3 = x1
s3 = [14,0,5,0,1,6,5,1,1,2,3,1,1,1,9,2,3,1,8,1,135,334,25,37,13,16,80,0,33,0,0,32,0,11,3,112,12,297,0,0,3,18,31,2,0,0,40,3,22,5,4,0,15,7,8,5,18]
c3 = "orange" #
m3 = "o" #"o"

#Paso 4
x4 = x1
s4 = [2,76,1,1,0,0,1,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,7,87,0,0,0,1,0,0,0,0,0,1,0,2,0,0,19,1,0,0,0,0,0,42,0,0,1,0,0,1,0,1,0,0,0]
c4 = "orange" #"red"
m4 = "o" #"x"

plt.scatter(x1, y1, c =c1, 
            linewidths = 2, 
            marker =m1, 
            edgecolor =c1, 
            s = s1)

plt.scatter(x2, y2, c =c2,
            linewidths = 2,
            marker =m2, 
            edgecolor =c2, 
            s = s2)

plt.scatter(x3, y3, c =c3,
            linewidths = 2,
            marker =m3, 
            edgecolor =c3, 
            s = s3)

plt.scatter(x4, y4, c =c4,
            linewidths = 2,
            marker =m4, 
            edgecolor =c4, 
            s = s4)


plt.xticks(rotation=90)
plt.xlabel("Tipos de ataque")
#plt.ylabel("Etapa")
#plt.show()
plt.title('Distribución de los ataques')
plt.savefig('imagen-Resumen-reglas.svg', dpi=400, format='svg', bbox_inches='tight')
plt.savefig('imagen-Resumen-reglas.png', dpi=400, format='png', bbox_inches='tight')