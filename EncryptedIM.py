#!/usr/bin/python

#Original Author : Henry Tan

#An encrypted P2P Instant Messenger using AES-128 encryption in CBC mode and HMAC with SHA-256 for authentication.
#sources:
#pycrypto documentation
#https://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes

import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Random import get_random_bytes

from collections import deque

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
logger = logging.getLogger('main')
###########


def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.') #create argumentparser object and tell it what args to expect
  #fill argparser object with information about program's args
  parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to') #defining arguments, value is saved to connect argument in dest
  parser.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  parser.add_argument('port', metavar='PORT', type=int,
    default = DEFAULT_PORT, nargs='?',
    help = 'For testing purposes - allows use of different port')
  parser.add_argument('-confkey', dest='confkey', metavar='K1', type=str, required=True, help ='Confidentiality key')
  parser.add_argument('-authkey', dest='authkey', metavar='K2', type=str, required=True, help='Authorization key')

  return parser.parse_args() #called with no arguments because will automatically determine command line args from sys.argv


def print_how_to():
  print ("This program must be run with exactly ONE of the following options")
  print ("-c <HOSTNAME> <PORT> -confkey <K1> -authkey <K2>  : to connect to <HOSTNAME> on tcp port <portnum> (default port 9990)")
  print ("-s <PORT> -confkey <K1> -authkey <K2>             : to run a server listening on tcp port <portnum> (default port 9999)")

def sigint_handler(signal, frame):
  logger.debug("SIGINT Captured! Killing")
  global s, server_s
  if s is not None:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
  if server_s is not None:
    s.close()

  quit()

def init():
  global s, ip, confkey, authkey
  args = parse_arguments()

  logging.basicConfig() #for logging system to look at flow of application
  logger.setLevel(logging.CRITICAL) #most severe level

  #Catch the kill signal to close the socket gracefully
  signal.signal(signal.SIGINT, sigint_handler)

  #hash k1
  k1 = SHA256.new()
  k1.update(bytes(args.confkey, encoding='utf-8'))
  #get first 128 bits
  confkey = k1.digest() #confkey is type byte string
  confkey = confkey[:16]
  #print(confkey)

  #hash k2
  k2 = SHA256.new()
  k2.update(bytes(args.authkey, encoding='utf-8'))
  #get first 128 bits
  authkey = k2.digest() #authkey is type byte string
  authkey = authkey[:16]
  #print(authkey)

  if args.connect is None and args.server is False: #actng as server and client- incompatible
    print_how_to()
    quit()

  if args.connect is not None and args.server is not False: #acting as client and server- incompatible
    print_how_to()
    quit()

  if args.connect is not None: #acting as client, then create socket and connect to it
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create socket object
    logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
    ip = socket.gethostbyname(args.connect)
    s.connect((ip, args.port)) #connect(host ip, port)

  if args.server is not False: #acting as server
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port)) #bind to the port; input empty string in ip field so server listens to requests from other computers on the network
    server_s.listen(1) #Only one connection at a time, allows server to accept connections
    s, remote_addr = server_s.accept() #establish connection with client
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))

def main():
  global s
  datalen=64

  init()


  inputs = [sys.stdin, s] #objects to check for incoming data to be read
  outputs = [s] #objects that will receive outgoing data (write to) when theres room in their buffer

  output_buffer = deque() #double ended queue, can add and remove elements from both ends

  while s is not None:
    #Prevents select from returning the writeable socket when there's nothing to write
    if (len(output_buffer) > 0):
      outputs = [s]
    else: #theres nothing to write so don't return writeable socket
      outputs = []

    readable, writeable, exceptional = select.select(inputs, outputs, inputs)

    if s in readable: #s is established connection with client that has sent data
      #take bytes from socket and print to console
      received_iv = s.recv(16) #know that iv is always 16 bytes (length of encryption block)
      #print('next line is iv gotten from socket')
      #print(received_iv) #get iv

      received_hmac = s.recv(32) #get hmac which is fixed length 64 bytes
      #print('next line is hmac gotten from socket')
      #print(received_hmac)

      #take in encrypted message
      data = s.recv(1024)
      if ((data is not None) and (len(data) > 0)):
        #verify hmac
        h2 = HMAC.new(authkey, digestmod=SHA256)
        h2.update(data)
        #print(h2.digest())
        if (h2.digest() != received_hmac):
           sys.exit("The message is not authentic! Exited program.")
        #decrypt the message
        obj2 = AES.new(confkey, AES.MODE_CBC, received_iv)
        decrypted = obj2.decrypt(data)
        #print(decrypted)
        padding_bytes = decrypted[-1]
        #print("padding byte is %s" %padding_bytes)
        #print(padding_bytes)
        if (padding_bytes != 10): #if no padding needed then last character is \n which corresponds to padding_byte 10
           decrypted = decrypted[:-padding_bytes]
        sys.stdout.write(decrypted.decode('utf-8')) #Assuming that stdout is always writeable #get hmac

      else:
        #Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable: #read input message and put it in output buffer
      data = sys.stdin.readline(1024)

      #create IV
      iv = get_random_bytes(AES.block_size)
      #print(iv)

      #encrypt the message
      length = len(data)
      #print("length of message is %s" %length)
      if ((len(data) % 16) != 0): #message size is not a multiple of 16 byte encryption blocks
        data = data + (16-(len(data)%16)) * chr(16-(len(data)%16)) #pad end of message with length of bytes padded repeated length times
        #print(data)
      obj = AES.new(confkey, AES.MODE_CBC, iv)
      ciphertext = obj.encrypt(data)
      #print(ciphertext)

      #create HMAC
      hmac = HMAC.new(authkey, digestmod=SHA256)
      hmac.update(ciphertext)
      #print (hmac.hexdigest()) #prints string version of hmac
      #print (len(hmac.digest())) #prints length of byte string hmac to figure out fixed size of all hmacs

      entiremsg = b"".join([iv, hmac.digest(), ciphertext]) #join iv, hmac (byte string version), and ciphertext in one byte string
      #print (entiremsg)
      #print (len(entiremsg))

      if(len(data) > 0):
        output_buffer.append(entiremsg)
      else:
        #EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable: #take data from output buffer and put it in socket s
      if (len(output_buffer) > 0):
        #put iv in socket
        data = output_buffer.popleft()
        bytesSent = s.send(data)
        #print("number of bytes sent is %s" %bytesSent)


        #If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:]) #append rest of unwritten bytes to front of deque

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None

###########

if __name__ == "__main__":
  main()
