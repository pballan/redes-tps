import sys
from scapy.all import *
from time import *
import matplotlib.pyplot as plt

MILLISECONDS = 1000
MAX_TTL = 31
PROBES_PER_TTL = 30
TIME_EXCEEDED_TYPE = 11
ECHO_REPLY_TYPE = 0

def traceroute(url):
    responses = {ttl: [] for ttl in range(1, MAX_TTL+1)}
    max_ttl = MAX_TTL + 1
    for ttl in range(1,MAX_TTL+1):
        print("asda")
        if ttl > max_ttl:
            return responses
        for attempt in range(PROBES_PER_TTL):
            probe = IP(dst=url, ttl=ttl) / ICMP()
            tiempo_inicio = time()
            # Send and receive one packet
            # https://scapy.readthedocs.io/en/latest/usage.html#send-and-receive-packets-sr
            ans = sr1(probe, verbose=False, timeout=0.8)
            tiempo_final = time()
            rtt = (tiempo_final - tiempo_inicio)*MILLISECONDS
            if ans is not None:
                icmp_type = ans[ICMP].type
                if icmp_type == TIME_EXCEEDED_TYPE or icmp_type == ECHO_REPLY_TYPE:
                    responses[ttl].append({'ip': ans.src, 'rtt': rtt})
                if icmp_type == ECHO_REPLY_TYPE:
                    max_ttl = ttl
    return responses

def most_visited_ip(probes):
    ips_seen = {}
    for result in probes:
        ip = result['ip']
#         print(f'ip: {ip}')
        if ip not in ips_seen:
            ips_seen[ip] = 1
        else:
            ips_seen[ip] += 1
#     print(ips_seen)
    return max(ips_seen, key=ips_seen.get)

# Returns dictionary of results but only those that visited the most visited IP
def filter_by_most_visited_ip(results):
    res = {}
    for ttl, probes in results.items():
        if len(probes) == 0:
            continue
        filter_ip = most_visited_ip(probes)
        res[ttl] = [probe for probe in probes if probe['ip'] == filter_ip]
    return res

# Average of all values in a list of numbers
def average(lst):
    return sum(lst) / len(lst)
        
# Returns the average rtt for a list of probes
def average_rtt(probes):
#     print(f'avg for {probes}')
    return average([result['rtt'] for result in probes])
        
# Returns a dict of (ttl, average_rtt) with the average_rtt of all probes for that TTL
def dict_of_average_rtt(results):
    average_dict = {}
    for ttl, probes in results.items():
        if len(probes) == 0:
            continue
        average = average_rtt(probes)
        average_dict[ttl] = {'ip': probes[0]['ip'], 'average_rtt': average}
    return average_dict

# Takes a dict of (ttl, average_rtt)
# Returns a dict of (hops, difference)
def rtt_per_hops(averaged_results):
    retorned = []
    previous_ttl = 1
    for ttl, results in averaged_results.items():
        rtt = results['average_rtt']
        if ttl > 1:
            print(f'rtt between {results["average_rtt"]}, {averaged_results[previous_ttl]["average_rtt"]}')
            rtt = results['average_rtt'] - averaged_results[previous_ttl]['average_rtt']
            if rtt < 0:
                print('rtt is negative')
                continue
            previous_ttl = ttl
        retorned.append({'ttl': ttl, 'rtt': rtt})
    return retorned



universidades = {
    'AmericaNorte': 'www.harvard.edu',
    'AmericaSur': 'www.uchile.cl',
    'Europa': 'www.ox.ac.uk',
    'Africa': 'www.unn.edu.org',
    'Asia': 'www.pku.edu.cn',
    'Oceania': 'www.anu.edu.au',
}

res = traceroute('www.anu.edu.au')

print(res)
print("\n")
_most_visited_ip = filter_by_most_visited_ip(res)
print(_most_visited_ip)
print("\n")
avgs = dict_of_average_rtt(_most_visited_ip)
print(avgs)

print("\n")
ret = rtt_per_hops(avgs)
print(ret)

plt.plot([res["ttl"] for res in ret], [res["rtt"] for res in ret], 'b.-')
plt.title("RTT entre saltos")
plt.ylabel("RTT en milisegundos")
plt.xlabel("TTLs")
plt.xticks(range(1,14))
plt.show()