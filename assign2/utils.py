from urllib.parse import urlparse
import os

def get_base_url(url):
  if '//' not in url:
    url = '%s%s' % ('http://', url)
  parsed_uri = urlparse(url)
  result = 'www.{uri.netloc}'.format(uri=parsed_uri)
  return result

def block_os_from_sending_rst():
  pf_conf_str = 'block drop proto tcp from any port 9000:9999 to any flags R/R'
  os.system("echo '%s' >> /etc/pf.conf" % pf_conf_str)
  os.system('pfctl -f /etc/pf.conf')
  os.system('pfctl -e')

def unblock_os_from_sending_rst():
  os.system("sed -i '' '$d' /etc/pf.conf")