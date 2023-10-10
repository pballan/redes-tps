#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
from statistics import mean
from itertools import product
import requests

###########
url = "http://ipinfo.io/"
miIP = "http://ipinfo.io/ip"
###########
def obtenerDatosAproximadosDe(ip):
    #Esta funcion devuelve un json los datos a los
    #que se puede acceder son: 'ip', 'city', 'region', 'country', 'loc', 'org', 'timezone'
    #donde 'loc' son las coordenadas para ubicarlo en maps
    request = requests.get( url + ip )
    #supogo q no devuelve error la pagina
    data = request.json()
    return data

def obtenerMiIp():
    request = requests.get(miIP)
    return request.text

responses = {}
#un diccionario de diccionarios
#{ ttl , { IP, [rtts] } }

_ips_recorridas = {}
_intersaltos_por_ip = {}
_intersaltos_filtrados = {}
universidades = {
    'AmericaNorte': 'www.harvard.edu',
    'AmericaSur': 'www.uchile.cl',
    'Europa': 'www.ox.ac.uk',
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
    ttl_previo = 0
    rtt_previo = 0
    rtt_total = 0
    ip_previo = obtenerMiIp()
    _intersaltos_por_ip[ttl_previo] = (ip_previo, 0.0)
    _intersaltos_filtrados[ttl_previo] = (ip_previo, 0.0)

    for ttl, intent in responses.items():
        #_intersaltos_por_ip[ttl] = []
        obtenerMayorPorPromedio( ttl, intent )

    
    for ttl in _intersaltos_por_ip:
        if ttl != 0:
            if _intersaltos_por_ip[ttl][1] > _intersaltos_por_ip[ttl_previo][1]:
                _intersaltos_filtrados[ttl] = _intersaltos_por_ip[ttl]
                ttl_previo = ttl
    ttl_previo = 0
    for ttl in _intersaltos_filtrados:
        if ttl != 0:
            #coord = obtenerDatosAproximadosDe( _intersaltos_filtrados[ttl][0] )["loc"]
            _intersaltos_filtrados[ttl] = (_intersaltos_filtrados[ttl][0], _intersaltos_filtrados[ttl][1], _intersaltos_filtrados[ttl][1] - _intersaltos_filtrados[ttl_previo][1])#, coord  )
            ttl_previo = ttl

def obtenerIPsVisitadas():
    for ttl, intent in responses.items():
        _ips_recorridas[ttl] = []
        for ip in intent.keys():
            if ip != 'unans':
                _ips_recorridas[ttl].append( ip )

for ttl in range(1, 30):
    for _ in range(2):
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
imprimir(_intersaltos_filtrados)


#calcular RTT entre cada salto para los que se recibe una respuesta time exceeded
#diferenciar rutas
# #calcular valor promedio entre cada salto