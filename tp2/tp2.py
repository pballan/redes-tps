#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
from statistics import mean
from itertools import product
import requests
import csv

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
    #para cada ttl me quedo con la lista de mayor longitud y a esa lista le calculo el promedio.
    #luego, defino en _intersaltos_por_ip[ttl] la tupla <IP, promedio de lista mas larga>
    if not intent or all( key == 'unans' for key in intent.keys() ):
        return
    else:
        max_pair = max(
            ((ip, rtts ) for ip, rtts in intent.items() if ip != 'unans'),
            key=lambda x: len(x[1]),default=None)
        _intersaltos_por_ip[ttl] = (max_pair[0], mean(max_pair[1]))


def obtenerIntersaltosPorIP():
    ttl_previo = 1
    #ip_previo = obtenerMiIp()

    for ttl, intent in responses.items():#obtengo para cada ttl la ip con el promedio de la lista mas larga
        obtenerMayorPorPromedio( ttl, intent )
    #_intersaltos_por_ip[1] = ( ip_previo, _intersaltos_por_ip[1][1])
    _intersaltos_filtrados[1] = _intersaltos_por_ip[1]
    for ttl in _intersaltos_por_ip: #nos quedamos con las ips que no generen diferencias negativas entre ttl{i+1}-ttl{i}
        if ttl != 1:
            if _intersaltos_por_ip[ttl][1] > _intersaltos_por_ip[ttl_previo][1]:
                _intersaltos_filtrados[ttl] = _intersaltos_por_ip[ttl]
                ttl_previo = ttl
    #obtencion de coordenadas?
    ttl_previo = 1
    for ttl in _intersaltos_filtrados:
        if ttl != 0:
            coord = obtenerDatosAproximadosDe( _intersaltos_filtrados[ttl][0] ) #( ip, promTTL, promedio salto anterior, coord )
            if "loc" in coord:
                _intersaltos_filtrados[ttl] = (_intersaltos_filtrados[ttl][0], _intersaltos_filtrados[ttl][1], _intersaltos_filtrados[ttl][1] - _intersaltos_filtrados[ttl_previo][1], coord["loc"]  )
            else:
                _intersaltos_filtrados[ttl] = (_intersaltos_filtrados[ttl][0], _intersaltos_filtrados[ttl][1], _intersaltos_filtrados[ttl][1] - _intersaltos_filtrados[ttl_previo][1], "noLocAv"  )
            ttl_previo = ttl

def obtenerIPsVisitadas():
    #ips visitadas arama el diccionario _ips_recorridas. para cada ttl se arma una lista de IPs por las que pasa en esa instancia.
    #responses: diccionario <ttl, dicc<IP, [rtts]> >
    for ttl, intent in responses.items():
        #para cada ttl creamos un campo en _ips_recorridas con la lista vacias
        #_ips_recorridas:  <ttl, [ip] >
        _ips_recorridas[ttl] = []
        for ip in intent.keys():
            #para cada IP por la que pasa en una instancia de ttl y que no es 'unans' la agrego a _ips_recorridas
            if ip != 'unans':
                _ips_recorridas[ttl].append( ip )
def _traceroute_( url_dst ):
    for ttl in range(1, 30):
        for _ in range(30):
            probe = IP(dst=url_dst, ttl=ttl) / ICMP()
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


    obtenerIPsVisitadas()
    imprimir( _ips_recorridas )
    obtenerIntersaltosPorIP()
    imprimir( _intersaltos_por_ip )
    imprimir(_intersaltos_filtrados)

def to_csv( aNameContinent ):
    nameFile = aNameContinent + ".csv"
    if os.path.isfile( nameFile ):
        os.remove( nameFile )
    with open( nameFile, 'w', newline='' ) as f:
        writer = csv.writer(f)
        writer.writerow( ("ttl", "rttMean", "rttPrev", "coord") )
        for ttl in _intersaltos_filtrados:
            writer.writerow( _intersaltos_filtrados[ttl] )

def main():
    for continent in universidades:
        _traceroute_( universidades[continent] )
        to_csv( continent )
        responses.clear()
        _ips_recorridas.clear()
        _intersaltos_por_ip.clear()
        _intersaltos_filtrados.clear()

    return

if __name__== "__main__":
    main()

#calcular RTT entre cada salto para los que se recibe una respuesta time exceeded
#diferenciar rutas
# #calcular valor promedio entre cada salto