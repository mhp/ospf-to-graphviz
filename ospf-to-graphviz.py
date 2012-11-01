#!/usr/bin/env python
#
# OSPF Multicast Sniffer and graphviz graph generator 
# 
# Listens to multicast group 224.0.0.5 (AllSPFRouters), processes
# LS Update messages and generates a graphviz network graph.
# To convert to image file, use:
#   ospf-to-graphviz.py mynetwork.dot
#   dot -Tpng mynetwork.dot >mynetwork.png
#
# Based on initial code by Ferdy Riphagen:
# http://code.activestate.com/recipes/576664-ospf-multicast-sniffer/
#

import socket
import sys
import datetime
import netaddr

MCAST_GROUP = '224.0.0.5'
PROTO_OSPF = 89

OSPF_TYPE_IGP = 0x59
HELLO_PACKET = 1
DB_DESCRIPTION = 2
LS_REQUEST = 3
LS_UPDATE = 4
LS_ACKNOWLEDGE = 5


def mkNetInt(r):
  if len(r)==1:
    return ord(r[0])
  else:
    return ord(r[0])*256 + mkNetInt(r[1:])


def safeIPAddr(ip):
  return str(ip).replace('.', '_')


def destNW(ip, networks):
  for nw in networks:
    if (ip & networks[nw].netmask) == nw:
      return nw
  return None


class OSPF_LSA_Header(object):
  def __init__(self, data):
    self.age = mkNetInt(data[0:2])
    self.options = ord(data[2])
    self.type = ord(data[3])
    self.lsid = netaddr.IPAddress(socket.inet_ntoa(data[4:8]))
    self.advrouter = netaddr.IPAddress(socket.inet_ntoa(data[8:12]))
    self.seq = mkNetInt(data[12:16])


class OSPF_LSA_Router(OSPF_LSA_Header):
  class Link(object):
    linkTypes = { 1: 'p2p to router', 2: 'transit n/w', 3: 'stub n/w', 4: 'virtual link' }
    def __init__(self, data):
      self.id = netaddr.IPAddress(socket.inet_ntoa(data[0:4]))
      self.data = netaddr.IPAddress(socket.inet_ntoa(data[4:8]))
      self.type = ord(data[8])
      self.metric = mkNetInt(data[10:12])
    def __str__(self):
      return '%s (%d): %s [%s], %d' % (self.linkTypes[self.type], self.type, self.id, self.data, self.metric)

  def __init__(self, data):
    OSPF_LSA_Header.__init__(self, data)
    self.links=[]
    l = data[24:]
    while len(l) > 0:
      self.links.append(self.Link(l[0:12]))
      l = l[12:]

  def __str__(self):
    return ', '.join([str(self.lsid), str(self.advrouter), '\n[ '+'\n  '.join([str(l) for l in self.links])+'\n]'])


class OSPF_LSA_Network(OSPF_LSA_Header):
  def __init__(self, data):
    OSPF_LSA_Header.__init__(self, data)
    self.netmask = netaddr.IPAddress(socket.inet_ntoa(data[20:24]))
    data = data[24:]
    self.attached = []
    while len(data) > 0:
      self.attached.append(netaddr.IPAddress(socket.inet_ntoa(data[0:4])))
      data = data[4:]

  def __str__(self):
    return ', '.join([str(self.lsid), str(self.advrouter), str(self.netmask), '{'+', '.join([str(a) for a in self.attached])+'}'])


class OSPF_LS_Update(object):
  lsTypes = { 1: ('Router-LSAs', OSPF_LSA_Router), 2: ('Network-LSAs', OSPF_LSA_Network) }
  def __init__(self, data):
    self.routerID = netaddr.IPAddress(socket.inet_ntoa(data[4:8]))
    self.areaID = netaddr.IPAddress(socket.inet_ntoa(data[8:12]))
    self.lsa = []

    numLSAs = mkNetInt(data[24:28])
    lsas = data[28:]
    for i in range(numLSAs):
      lsaLen = mkNetInt(lsas[18:20])
      lsType = ord(lsas[3])
      if lsType in self.lsTypes:
        self.lsa.append(self.lsTypes[lsType][1](lsas[0:lsaLen]))
      lsas=lsas[lsaLen:]


class NetworkModel(object):
  def __init__(self):
    self.networks={}
    self.routers={}
    self.changed = False

  def injectLSA(self, lsa):
    if lsa.type == 2:
      network = lsa.lsid & lsa.netmask
      if not self.networks.has_key(network) or lsa.seq > self.networks[network].seq:
        self.networks[network] = lsa
        self.changed = True
      #else:
      #  print "N/W lsa is old", lsa
      #for i in self.networks:
      #  print i, self.networks[i]
      #print '-'*30
    elif lsa.type == 1:
      if not self.routers.has_key(lsa.lsid) or lsa.seq > self.routers[lsa.lsid].seq:
        self.routers[lsa.lsid] = lsa
        self.changed = True
      #else:
      #  print "Router lsa is old", lsa
      #for i in self.routers:
      #  print i, self.routers[i]
      #print '-'*30
    else:
      print "Unknown LSA!", lsa.type

  def generateGraph(self):
    out = []
    out.append('graph ospf_nw {')
    out.append('  layout=fdp;')
    out.append('  label="Generated: %s";' % str(datetime.datetime.utcnow()))
    out.append('  node [shape="box",style="rounded"];')

    for r in self.routers:
      out.append('  subgraph cluster_%s {' % safeIPAddr(r))
      out.append('    label = "%s";' % r)
      for iface in self.routers[r].links:
        if iface.type == 2:
          out.append('    N%s [label="%s"];' % (safeIPAddr(iface.data), iface.data ))
      out.append('  }');

    for nw in self.networks:
      out.append('  nw_%s [shape="plaintext",label="%s/%s"];' % (safeIPAddr(nw), nw, self.networks[nw].netmask.bin.count('1') ))

    for r in self.routers:
      for iface in self.routers[r].links:
        if iface.type == 2:  # transit n/w
          out.append('  N%s -- nw_%s [label="%s"];' % (safeIPAddr(iface.data), safeIPAddr(destNW(iface.data, self.networks)), iface.metric))
        elif iface.type == 3:  # stub n/w
          out.append('  stub_%s [shape="doubleoctagon",label="%s/%s"];' % (safeIPAddr(iface.id), iface.id, iface.data.bin.count('1')))
          out.append('  cluster_%s -- stub_%s [label="%s"];' % (safeIPAddr(r), safeIPAddr(iface.id), iface.metric))

    out.append('}')
    self.changed = False
    return '\n'.join(out)

nw = NetworkModel()

def processPacket(addr, data):
  pos = 0
  # Message Type 
  if ord(data[pos+1]) == LS_UPDATE:
    #print "LS Update (%d)" % (ord(data[pos+1]),)
    z=OSPF_LS_Update(data[pos:])
    for l in z.lsa:
      nw.injectLSA(l)

    if nw.changed:
      if graphFile:
        f=open(graphFile, 'w')
        f.write(nw.generateGraph())
        f.close()
      else:
        print nw.generateGraph()

graphFile = None

if __name__ == '__main__':

  if len(sys.argv) == 2:
    graphFile = sys.argv[1]

  print "Output file:", graphFile

  listenIP='0.0.0.0'
  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, PROTO_OSPF)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MCAST_GROUP) + socket.inet_aton(listenIP))

  while True:
    try:
      data, addr = sock.recvfrom(10240)
      if data and ord(data[9]) == OSPF_TYPE_IGP:
        processPacket(addr, data[20:])
    except KeyboardInterrupt:
      sys.exit()
