#!/usr/bin/env python3
from scapy.all import *
from sys import argv
from math import log2

def source_info(source):
    n = sum(source.values())
    print('Total de paquetes:', n)
    entropy = 0
    for symbol in source:
    	p = source[symbol] / n
    	i = -log2(p)
    	entropy += p * i
    	print(F"{symbol} | {p * 100:.5f} % | {i:.5f} bits")

    print(F"Entropía: {entropy:.5f}")
    print(F"Entropía máxima: {log2(n):.5f}")

def main() -> int:

	if len(argv) < 2:
		print("Parámetros: <file>.pcapng", file=sys.stderr)
		return 1

	file = argv[1]
	capture = rdpcap(file)

	source = dict() 
	for packet in capture:
		if packet.haslayer(Ether):
			transmission = "BROADCAST" if packet[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
			symbol = (transmission, packet[Ether].type)
			if symbol not in source:
				source[symbol] = 0.0
			source[symbol] += 1.0

	source_info(source)

if __name__ == '__main__':
	main()