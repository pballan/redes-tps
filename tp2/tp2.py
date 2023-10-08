#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
from statistics import mean
from itertools import product



responses = {}
#un diccionario de diccionarios
#{ ttl , { IP, [rtts] } }

_ips_recorridas = {}
_intersaltos_por_ip = {}
universidades = {
    'AmericaNorte': 'www.harvard.edu',
    'AmericaSur': 'www.uchile.cl',
    'Europa': 'www,ox.ac.uk',
    'Africa': 'www.unn.edu.org',
    'Asia': 'www.pku.edu.cn',
    'Oceania': 'www.anu.edu.au',
}
def imprimir(diccionario):
    for key, value in diccionario.items():
        print(key)
        print('\t', value)
def obtenerMayorPorPromedio( ttl, intent ): #intent es diccionario { IP, [rtts] }
    if not intent or all( key == 'unans' for key in intent.keys() ):
        return
    else:
        max_pair = max(
            ((ip, rtts ) for ip, rtts in intent.items() if ip != 'unans'),
            key=lambda x: len(x[1]),default=None)
        _intersaltos_por_ip[ttl] = (max_pair[0], mean(max_pair[1]))

def obtenerIntersaltosPorIP():
    for ttl, intent in responses.items():
        #_intersaltos_por_ip[ttl] = []
        obtenerMayorPorPromedio( ttl, intent )

def obtenerIPsVisitadas():
    for ttl, intent in responses.items():
        _ips_recorridas[ttl] = []
        for ip in intent.keys():
            if ip != 'unans':
                _ips_recorridas[ttl].append( ip )

for ttl in range(1, 25):
    for _ in range(5):
        probe = IP(dst=sys.argv[1], ttl=ttl) / ICMP()
        t_i = time()
        ans = sr1(probe, verbose=False, timeout=0.8)
        t_f = time()
        rtt = (t_f - t_i) * 1000

        if ans is not None:
            if ttl not in responses:
                responses[ttl] = {}
            responses[ttl].setdefault(ans.src, []).append(rtt)
        else:
            if ttl not in responses:
                responses[ttl] = {}
            responses[ttl].setdefault('unans', []).append(rtt)



#print( responses )
#for ttl, intent in responses.items():
#    print(ttl)
#    #print(intent)
#    for ip, rtts in intent.items():
#        print('\t', ip)
#        print('\t\t', rtts)

obtenerIPsVisitadas()
imprimir( _ips_recorridas )
obtenerIntersaltosPorIP()
imprimir( _intersaltos_por_ip )

#calcular RTT entre cada salto para los que se recibe una respuesta time exceeded
#diferenciar rutas
# #calcular valor promedio entre cada salto