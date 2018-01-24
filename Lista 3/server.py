import BaseHTTPServer, SimpleHTTPServer
import ssl
import os

port = 8010
keypath = os.path.abspath('privkeyA.pem')
certpath = os.path.abspath('certA.crt')

httpd = BaseHTTPServer.HTTPServer(('localhost', port), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket,keyfile =keypath, certfile=certpath, server_side=True)
print("serving at port", port)
httpd.serve_forever()

#python server.py
#https://localhost:8010/
