#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *

responses = {}
#un diccionario de diccionarios
#ttl -> {<IP, [rtts]>}

for ttl in range(1,25): #
    for i in range(5):
        probe = IP(dst=sys.argv[1], ttl=ttl) / ICMP()
        t_i = time()

        ans = sr1(probe, verbose=False, timeout=0.8) #unans?

        t_f = time()

        rtt = (t_f - t_i)*1000

        if ans is not None:
            if ttl not in responses:
                responses[ttl] = {}
                responses[ttl][ans.src] = [rtt]
            #responses[ttl].append((ans.src, rtt))

            if ttl in responses:
                if ans.src not in responses[ttl]:
                    responses[ttl][ans.src] = [rtt]
                else:
                    responses[ttl][ans.src].append(rtt)
                #print(ttl, responses[ttl])
        else: # si no hubo respuesta
            if ttl not in responses:
                responses[ttl] = {}
                responses[ttl]['unans'] = [rtt]
            else:
                if 'unans' in responses[ttl]:
                    responses[ttl]['unans'].append(rtt)
                else:
                    responses[ttl]['unans'] = [rtt]
#print( responses )
for key in responses:
    print(key)
    for values in responses[key]:
        print(values)