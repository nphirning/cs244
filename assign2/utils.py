from scapy.all import *
from urllib.parse import urlparse
import os

def get_base_url(url):
  if '//' not in url:
    url = '%s%s' % ('http://', url)
  parsed_uri = urlparse(url)
  result = 'www.{uri.netloc}'.format(uri=parsed_uri)
  
  return result

def block_os_from_sending_rst():
  pf_conf_str = 'block drop proto tcp from any port 9000:9999 to any flags R/R '
  pf_conf_str += '>/dev/null 2>&1'
  os.system("echo '%s' >> /etc/pf.conf" % pf_conf_str)
  os.system('pfctl -f /etc/pf.conf >/dev/null 2>&1')
  os.system('pfctl -e >/dev/null 2>&1')

def unblock_os_from_sending_rst():
  os.system("sed -i '' '$d' /etc/pf.conf >/dev/null 2>&1")

def reset_connection(target):
  rst = create_tcp_packet(target, 1000, 'R', seq_no, MSS)
  send(rst)

def create_tcp_packet(target, seq_no, flags, ack_no, mss, src_port):
  ip = IP(dst=target)
  opt = [('MSS', mss)]
  if ack_no is None:
    tcp = TCP(dport=80, sport=src_port, flags=flags, seq=seq_no, options=opt) 
  else:
    tcp = TCP(dport=80, sport=src_port, flags=flags, seq=seq_no, ack=ack_no, options=opt)
  return ip / tcp