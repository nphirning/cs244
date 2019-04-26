from scapy.all import *
from utils import *
import argparse
import time
import random

SRC_PORT = random.randint(9001, 9998)
START_SEQ = random.randint(1000, 2000)
MSS = 64

# Number of seconds to wait for new data after sending an ACK. This is used to
# determine if the output was actually limited by the ICW.
CHECK_IF_LIMITED_TIMEOUT = 3

def create_TCP_packet(target, seq_no, flags, ack_no):
  ip = IP(dst=target)
  opt = [('MSS', MSS)]
  if ack_no is None:
    tcp = TCP(dport=80, sport=SRC_PORT, flags=flags, seq=seq_no, options=opt) 
  else:
    tcp = TCP(dport=80, sport=SRC_PORT, flags=flags, seq=seq_no, ack=ack_no, options=opt)
  return ip / tcp

def do_tcp_handshake(target, verbose=False):
  
  # Step 1. Send SYN and receive SYN-ACK.
  syn_packet = create_TCP_packet(target, START_SEQ, 'S', None)
  ans, unans = sr(syn_packet, verbose=verbose)
  syn_response = ans[0][1]
  if not syn_response['TCP'] or syn_response['TCP'].flags != 'SA':
    print("Response was not a SYNACK.")
    return
  seq_num = syn_response['TCP'].seq
  
  # Step 2. Send ACK with GET request.
  ack_packet = create_TCP_packet(target, START_SEQ+1, 'A', seq_num+1)
  get_str = 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % target
  send(ack_packet / get_str, verbose=verbose)

def listen_until_retransmission(target):
  packets = []
  seq_nums_seen = []
  def stop_filter(pkt):
    if len(pkt['TCP'].payload) > 0:
      if pkt['TCP'].seq in seq_nums_seen:
        return True
      packets.append(pkt)
      seq_nums_seen.append(pkt['TCP'].seq)
    return False

  sniff(
    filter='host %s and port %s' % (target, SRC_PORT),
    stop_filter=stop_filter,
  )
  return (packets, seq_nums_seen)

global isLimited

def listen_for_new_pkts(target, maxSeqNo):
  global isLimited
  start = time.time()
  isLimited = False
  seq_nums_seen = []
  
  def stop_filter_on_new_data(pkt):

    # Timeout check.
    if time.time() - start > CHECK_IF_LIMITED_TIMEOUT:
      return True

    # Check for new data.
    global isLimited
    if len(pkt['TCP'].payload) == 0: return False
    if pkt['TCP'].seq > maxSeqNo:
      isLimited = True
      return True
    if time.time() - start > 2:
      return True
    seq_nums_seen.append(pkt['TCP'].seq)
    return False
  
  sniff(
    filter='host %s and port %s' % (target, SRC_PORT),
    stop_filter=stop_filter_on_new_data
  )

  return (isLimited, seq_nums_seen)

def close_connection(target, seq_no, verbose=False):
  rst = create_TCP_packet(target, seq_no, 'R', seq_no)
  send(rst, verbose=verbose)

def run_icw_test(target, verbose=False):

  if verbose: print("Contacting server at address %s" % target)
  close_connection(target, 1)
  time.sleep(1)

  # Create a connection and listen for re-transmission.
  block_os_from_sending_rst()
  do_tcp_handshake(target, verbose=verbose)
  if verbose: print("TCP handshake complete.")
  packets, seq_nums_seen = listen_until_retransmission(target)
  if verbose: print("Retransmission event observed. Acking first segment.")

  # After re-transmission, ACK a segment to detect if limited by ICW.
  maxSeqNo, payloadLen = max(
    [(pkt['TCP'].seq, len(pkt['TCP'].payload)) for pkt in packets]
  )
  #TODO: Is +40 corrrect here?
  nextAck = create_TCP_packet(target, START_SEQ+1+40, 'A', maxSeqNo + payloadLen)
  send(nextAck, verbose=verbose)

  # Listen for more packets to determine if limited by ICW.
  isLimited, seq_nums_seen = listen_for_new_pkts(target, maxSeqNo)
  if verbose: print("Connection is limited by ICW: %s" % isLimited)
  close_connection(target, START_SEQ+2)
  unblock_os_from_sending_rst()

  # Data extraction.
  maxMSS = max([len(pkt['TCP'].payload) for pkt in packets])
  response = ''.join([str(pkt['TCP'].payload) for pkt in packets])
  response = response[response.find('HTTP'):]
  statusCode = int(response[9:12])
  print("statusCode is:")
  print(statusCode)
  if maxMSS > MSS: isLimited = False
  location = None
  if statusCode == 301 or statusCode == 302:
    print("printing response:")
    print(response)
    idx = response.find('Location: ') + len('Location: ')
    print (idx, response.find("\n", idx))
    location = response[idx:response.find("\n", idx)-1]
    print("printing location")
    print(location)

  return (isLimited, maxMSS, len(packets), statusCode, location)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Run ICW test.')
  parser.add_argument('target', help='host you would like to target')
  args = parser.parse_args()

  target = args.target
  base_target = get_base_url(target)
  print(base_target)
  results = run_icw_test(base_target, verbose=True)
  print(results)
  

  if results[3] == 301:
    print("Retrying with %s" % results[4])
    run_icw_test(results[4], verbose=True)

