from scapy.all import *
from utils import *
import argparse
import time
import random

SRC_PORT = random.randint(9001, 9998)
START_SEQ = random.randint(1000, 2000)
MSS = 64

# General timeout for sending packets.
TIMEOUT = 3

"""
  Initializes a connection to a hostname `target` with URL path `path`. This 
  initiates a TCP handshake and sends a HTTP 1.0 GET request with final ACK.
  
  Returns a tuple (success, msg_bytes), where `success` is true/false based on 
  whether the connection was successful and `msg_bytes` is set on a success to
  indicate the number of bytes in the TCP payload sent. 
"""
def init_connection(target, path):
  
  # Step 1. Send SYN.
  syn_packet = create_tcp_packet(target, START_SEQ, 'S', None, MSS, SRC_PORT)
  ans, unans = sr(syn_packet, timeout=TIMEOUT, verbose=False)
  if ans is None: return (False,)

  # Step 2. Receive SYN-ACK response.
  syn_response = ans[0][1]
  if not syn_response['TCP'] or syn_response['TCP'].flags != 'SA': return (False,)
  seq_num = syn_response['TCP'].seq
  
  # Step 3. Send final ACK with GET request.
  ack_packet = create_tcp_packet(target, START_SEQ+1, 'A', seq_num+1, MSS, SRC_PORT)
  long_target = target + "/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images/images"
  get_str = 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' % (path, target)
  send(ack_packet / get_str, verbose=False)
  return (True, len(get_str))

"""
  Listens to packets from a given host `target` and stops when a re-transmission
  occurs. If no retransmission events are observed, this will stop after
  3 * TIMEOUT seconds.

  Returns a tuple `(success, packets)` where `success` is true/false based on 
  whether or not a re-transmission event occurred and `packets` is a list of 
  the nonempty packets received before the re-transmission event.
"""
def listen_until_retransmission(target):
  retransmission_occurred = [False]
  packets = []
  seq_nums_seen = []
  def stop_filter(pkt):
    # Check if this is a retransmission.
    if TCP in pkt and len(pkt['TCP'].payload) == 0: return False
    if TCP in pkt and pkt[TCP].seq in seq_nums_seen:
      retransmission_occurred[0] = True 
      return True
    
    # Store information and continue. 
    packets.append(pkt)
    if TCP in pkt: seq_nums_seen.append(pkt['TCP'].seq)
    return False

  sniff(
    filter='host %s and port %s' % (target, SRC_PORT),
    stop_filter=stop_filter,
    timeout=TIMEOUT * 3
  )
  return (retransmission_occurred[0], packets)

"""
  Listens to packets from a given host `target` looking for nonempty packets
  with sequence number greater than `max_seq_no`. Stops when data is observed
  or on a timeout. 

  Returns true/false based on whether new data was observed.
"""
def listen_for_new_data(target, max_seq_no):
  
  is_limited = [False] # Work-around to access inside stop_filter_on_new_data.
  def stop_filter_on_new_data(packet):
    if TCP in packet and len(packet[TCP].payload) == 0: return False
    if packet[TCP].seq > max_seq_no:
      is_limited[0] = True
      return True
    return False
  
  sniff(
    filter='host %s and port %s' % (target, SRC_PORT),
    stop_filter=stop_filter_on_new_data,
    timeout=TIMEOUT
  )

  return is_limited[0]

"""
  Runs a single iteration of the ICW test for a host `target` with a URL path
  `path`.

  Returns a tuple (success, should_retry, num_packets, hint) where `success` is
  true/false based on whether or not the test succeeded. If the test succeeded,
  `num_packets` will be the number of (MSS-sized) packets in the ICW. If not, 
  then `should_retry` will be true/false based on whether the test thinks it 
  could succeed based on changes to the target. The `hint` recommends a new
  `target` within the host's network that may work.
"""
def run_icw_test(target, path):
  # Initial test of ICW.
  block_os_from_sending_rst()
  res = init_connection(target, path)
  if not res[0]: return (False, False)
  success, packets = listen_until_retransmission(target)
#  print(len(packets))
  if not success: return (False, False)


  # After re-transmission, ACK a segment and check if ICW was limiting.
  packet_data = [(pkt[TCP].seq, len(pkt[TCP].payload)) for pkt in packets]
  max_seq_no, payload_len = max(packet_data)
  ack_no = max_seq_no + payload_len
  next_seq_no = START_SEQ + 1 + res[1]
  next_ack = create_tcp_packet(target, next_seq_no, 'A', ack_no, MSS, SRC_PORT)
  send(next_ack, verbose=False)
  is_limited = listen_for_new_data(target, max_seq_no)

  # End connection.
  reset_connection(target, SRC_PORT)
  unblock_os_from_sending_rst()

  # Ensure that the MSS we specified was obeyed.
  max_mss = max([len(pkt[TCP].payload) for pkt in packets])
  if max_mss > MSS: return (False, False)

  # Handle success.
#  print("What", packets)
  if is_limited: return (True, None, len(packets))

  # On failure, extract response and handle based on status code.
  response = ''.join([str(pkt[TCP].payload) for pkt in packets])
  response = response[response.find('HTTP'):]
  status_code = int(response[9:12])
#  print(status_code, response, len(packets))
  if status_code == 301 or status_code == 302:
    idx = response.find('Location: ') + len('Location: ')
    location = response[idx:response.find("\n", idx)-1]
    return (False, True, len(packets), location)

  return (False, False)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Run ICW test.')
  parser.add_argument('target', help='host you would like to target')
  args = parser.parse_args()

  target = args.target
  base_target, path = get_base_url(target)
  res = run_icw_test(base_target, path)
#  print(res)
  if res[0]: print(res[2])
  elif res[1]:
    print(res[3])
  else:
    print("Nope")
  
  

  # if results[3] == 301 and results[0] == False:
  #   loc = results[4] + "/images/images/images/images"
  #   print("Retrying with %s" % loc)
  #   run_icw_test(results[4], verbose=True)

