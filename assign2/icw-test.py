from scapy.all import *
import argparse
from multiprocessing import Process

def do_tcp_handshake(target):
  
  # Step 1. Send SYN and receive SYN-ACK.
  syn_packet = IP(dst=target) / TCP(dport=80, flags='S', seq=1000)
  ans, unans = sr(syn_packet)
  syn_response = ans[0][1]
  if not syn_response['TCP'] or syn_response['TCP'].flags != 'SA':
    return
  seq_num = syn_response['TCP'].seq
  
  # Step 2. Send SYN-ACK.
  ack_packet = IP(dst=target) / TCP(dport=80, flags='A', seq=1001, ack=seq_num+1)
  ans, unans = sr(ack_packet)
  ack_response = ans[0][1]
  if not ack_response['TCP'] or ack_response['TCP'].flags != 'A':
    print('fuckkkk', ack_response['TCP'].flags)
    return
  
  print("Handshake complete.")
  return (1001, seq_num + 1)
  

def run_icw_test(target):

  do_tcp_handshake(target)

  # packet = IP(dst=target) / TCP(dport=80, flags='S', seq=1000)
  # print("Sending...")
  # ans, unans = sr(packet)
  # print("Received...", ans.summary())


  # # Create sniffing process.
  # p = Process(target=start_sniffer, args=(target,))
  # p.start()

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Run ICW test.')
  parser.add_argument('target', help='host you would like to target')
  args = parser.parse_args()
  run_icw_test(args.target)

