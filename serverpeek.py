# For the status code:
import requests

# lets pretend like we are not a script
user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
headers={'User-Agent':user_agent,} 

# ping
from pythonping import ping

# convert URL to domain
from urllib.parse import urlparse

#tcp connect, data stream
import urllib.request, urllib.error, urllib.parse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# convert domain to IP
import socket

# for timing milliseconds
import datetime

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

try:
    import httplib
except:
    import http.client as httplib

# colors
from colorama import init
init()

# when we do alert on a slow load time? (milliseconds)
ltimeThreshHold = 650


# define class for severcheck
class serverCheck():
    def __init__(self,uri,domain,text2check):

        self.error = 0
        dnstime1 = datetime.datetime.now()
        try:
            self.ip = socket.gethostbyname(domain)
        except:
            self.error = 1
        else:

            # we know it resolved because try sent us here
            # what is our IP?
            self.ip = socket.gethostbyname(domain)
            
            # take a time reading btw, so we can report on DNS response
            dnstime2 = datetime.datetime.now()
            delta = dnstime2 - dnstime1
            self.dns = int(delta.total_seconds() * 1000)

            # does it respond to ping?  
            #may or may not be up and may or not respond
            icmp = ping(self.ip, size=40, count=5)
            self.icmp = round(icmp.rtt_avg_ms)

            # crude port scan.  
            # several overhead calls, infefficient
            # just does quick handshake then hangs up
            # will definitely trigger IDS alarms
            self.t21 = portcheck(self.ip,21)
            self.t22 = portcheck(self.ip,22)
            self.t23 = portcheck(self.ip,23)
            self.t25 = portcheck(self.ip,25)
            self.t80 = portcheck(self.ip,80)
            self.t135 = portcheck(self.ip,135)
            self.t139 = portcheck(self.ip,139)
            self.t443 = portcheck(self.ip,443)
            self.t1433 = portcheck(self.ip,1433)
            self.t3306 = portcheck(self.ip,3306)

            # status code, has to do separate call to check if 403
            r = requests.head(uri)
            self.code = str(r.status_code)

            if r.status_code == 200 or r.status_code == 301 or r.status_code == 302:
                # handshake or figure out how to error on 403 safely
                req = urllib.request.Request(uri,None,headers) #, headers = {'user-agent':'Mozilla/5.0'})
                #req.add_header('User-Agent',"Mozilla/5.0")
                hshake1 = datetime.datetime.now()
                stream = urllib.request.urlopen(req)
                hshake2 = datetime.datetime.now()
                delta = hshake2 - hshake1
                self.shaket = int(delta.total_seconds() * 1000)

                # data stream load only if 200 or 
                data1 = datetime.datetime.now()
                self.bytes = round(len(stream.read())/1024)
                data2 = datetime.datetime.now()
                delta = data2-data1
                self.datat = int(delta.total_seconds() * 1000)

                # we know it responds favorably, so pull a text check
                r2 = requests.get(uri, verify=False)
                if text2check in r2.text:
                    self.textcheck = '\033[32m'+"YES"+'\033[30m'
                else:
                    # we are also going to highlight the background.  
                    # this is a hack, or database problem
                    self.textcheck = '\033[31m\033[43m'+"NO"+'\033[30m\033[49m'

                # color code our http status code
                self.code = '\033[32m'+str(self.code)+'\033[30m'
            elif r.status_code == 500:
                #default data, we cannot do these checks because of some reason
                self.shaket     = 9999
                self.datat      = '-N/A-'
                self.datalen    = '-N/A-'
                self.code       = '\033[31m\033[43m'+str(self.code)+'\033[30m\033[49m'
                self.bytes      = '-N/A-'
                self.textcheck  = '-N/A-'
            else:
                #default data, we cannot do these checks because of some reason
                self.shaket     = 9999
                self.datat      = '-N/A-'
                self.datalen    = '-N/A-'
                self.code       = '\033[31m'+str(self.code)+'\033[30m'
                self.bytes      = '-N/A-'
                self.textcheck  = '-N/A-'


        finally:
            self.default = "just something as a placeholder"


def checkServerNow(uri,domain,text2check):
    return serverCheck(uri,domain,text2check)

# port open or closed?
def portcheck(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout (0.5)
    result = sock.connect_ex((ip,port))
    sock.close()
    if result == 0:
        return '\033[31m'+"OPN"+'\033[30m'
    else:
        return '\033[37m'+"CLS"+'\033[30m'

# does it resolve, yes or no
# if yes, how long did it take
# if no, return 0
def dns(dom):
    try:
        socket.gethostbyname(dom)
        return 1
    except socket.error:
        return 0


def getDom(uri):
    spltAr = uri.split("://");
    i = (0,1)[len(spltAr)>1];
    dm = spltAr[i].split("?")[0].split('/')[0].split(':')[0].lower();
    return dm


# small dictionary/database of urls, and text to check on each.
# consider loading json files so customers can have data sets
uris = {
'https://rubysash.com/about/sitemap/' : 'Ruby Sash',
#'https://nas2:5001' : 'login',
#'https://rubysash.com/wp-admin/'  : 'wp-content',
#'https://rubysash.com/4040404/'  : 'wp-content',
#'https://www.microsoft.com/' : 'css',
}

print("DNS time only accurate on first run (Cached).\nAll measurements in ms.")
print('\033[33m'+"DNS\tICMP\t21\t22\t23\t25\t80\t135\t139\t443\t1433\t3306\tCODE\tSHAKE\tDATA\tKBYTE\tTEXT\tURL(AS PROVIDED)"+'\033[30m')

#for uri in uris:
for uri, textcheck in uris.items():
    
    # just regex and manipulate the URI to get DOM
    dom = getDom(uri)

    # create s object with all of the goodies in it.
    # pass in the URI, domain and string to check for
    # better to update uris as list of tuples so you can have unique checks
    s = checkServerNow(uri,dom,textcheck)
    
    # if it's no error, then do some stuff
    if s.error == 0:

        # dns formatting.    If it's more than 100ms, make it red
        dns = str(s.dns)
        if (s.dns > 100):
            dns = '\033[31m'+dns+'\033[30m'
        else:
            dns = '\033[32m'+dns+'\033[30m'

        # shaket
        if s.shaket > 750:
            shake = '\033[31m'+str(s.shaket)+'\033[30m' # red
        elif s.shaket < 750 and s.shaket > 500:            
            shake = '\033[33m'+str(s.shaket)+'\033[30m' # yellow
        else:
            shake = '\033[32m'+str(s.shaket)+'\033[30m' #green

        # datat
        datat = s.datat

        # ping isn't really a good measurement, as it can be low prioritized
        icmp = str(s.icmp)
        if (s.icmp > 60):
            icmp = '\033[31m'+icmp+'\033[30m'
        else:
            icmp = '\033[32m'+icmp+'\033[30m'

        # uri is just bright yellow info
        uri = '\033[33m'+uri+'\033[30m'

        # ok, print out our formatted stuff
        print(
            dns+"\t"+
            icmp+"\t"+
            str(s.t21)+"\t"+
            str(s.t22)+"\t"+
            str(s.t23)+"\t"+
            str(s.t25)+"\t"+
            str(s.t80)+"\t"+
            str(s.t135)+"\t"+
            str(s.t139)+"\t"+
            str(s.t443)+"\t"+
            str(s.t1433)+"\t"+
            str(s.t3306)+"\t"+
            str(s.code)+"\t"+
            shake+"\t"+
            str(s.datat)+"\t"+
            str(s.bytes)+"\t"+
            s.textcheck+"\t"+
            uri
            )
    
    else:
        # but if it is in an error, just say "error" and tell us basics
        print('\033[31m'+"FAIL\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+"-N/A-\t"+uri+'\033[30m')

    
