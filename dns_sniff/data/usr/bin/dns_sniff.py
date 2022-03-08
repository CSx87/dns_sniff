import socket
import binascii
import struct
import sys

#To clearly understand the unpacking go trough the structure of headers at each layers 
   
def unpack_ethernet(raw_data):
  dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])  #6s means a string of 6 bytes and H stands for integer
  proto = socket.htons(prototype)
  data = raw_data[14:]
  return proto,data 

#May require unpack_wifi also,Look into it.(Since router will query dns from ethernet usually so it may not be required but once check using raspberry pi)

def unpack_ipv4(raw_data):
   version_header_length = raw_data[0]
   version = version_header_length >> 4
   header_length = (version_header_length & 15) * 4
   ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
   data = raw_data[header_length:]
   return proto,data
   
def unpack_udp(data):
  src_port, dest_port, size, checksum = struct.unpack('! H H H H' , data[:8])
  return src_port, dest_port, size, data[8:]  
  

def unpack_dns(raw_data, udp_length):
  id, flags, question, Answer, Authority, add= struct.unpack('! H H H H H H', raw_data[:12])
  url_size = udp_length - 8 - 16
  format = '! '
  format = '! ' + str(url_size) + 's'
  last = 12 + url_size -1 
  name = struct.unpack(format,raw_data[12:last+1])
  return name[0].decode("utf-8")

# Look for any better method--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- 
def readable(s):
  
   l= []
   n = len(s)
   for i in range(0,n):
             
            if(s[i] == '\x01' or s[i] == '\x02' or s[i] == '\x03' or s[i] == '\n' or s[i]=='\t' or s[i] == '\x04' or s[i] == '\x05' or s[i] == '\x06' or s[i] == '\x07' or s[i] == '\x08' or s[i] == '\x09' or s=='\x0b') :
                l.append('.')
            elif(s[i] == '\x00' or s[i]== '\\'):
              pass
            else:
                l.append(s[i])
   return "".join(l)
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 
                       

#Getting the dns  
def main():
   s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
   while True:
      raw_data, addr = s.recvfrom(65535)
      eth = unpack_ethernet(raw_data)
      if eth[0] == 8: 
         ipv4 = unpack_ipv4(eth[1])
         
      if ipv4[0] == 17:
         udp = unpack_udp(ipv4[1])
         data = udp[3]
         size = udp[2]
         if(udp[1]==53):
             m = unpack_dns(data,size)
             n = readable(m[1:])
             update(n)
             #print('Updating data base with->',n) Try adding verbose print

#updating the dns to database
def update(str): 
  import sqlite3
  conn = sqlite3.connect('dns.db') #Connecting to database
  c = conn.cursor()
  
  if (len(c.execute("SELECT Names FROM dns WHERE Names = ?",[str]).fetchall())==0): #Checking if URL present in database
      c.execute("INSERT INTO dns VALUES(?,?)",[str,1]) #If not present INSERT the URL #? means the take the input from the list which is the second arg, 1st ? 1st element of list
  else: #IF present increase the no. of times visited
      c.execute("""
      UPDATE dns
      SET
          Visited = Visited + 1
      WHERE Names= ?
      """,[str])
  conn.commit()
  conn.close()



main()



