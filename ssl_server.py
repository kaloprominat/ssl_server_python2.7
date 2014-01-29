#!/usr/bin/env python  
#-*- coding:utf-8 -*-  

from bottle import Bottle, run, request, server_names, ServerAdapter, route, template, static_file, redirect, abort
from sslwsgiserver import CherryPyWSGIServerSSL


CERTFILE='certnew.cer'
PRIVKEYFILE='privkey.pem'
CAFILE='allcas.pem'

# Declaration of new class that inherits from ServerAdapter  
# It's almost equal to the supported cherrypy class CherryPyServer
class MySSLCherryPy(ServerAdapter):  
    def run(self, handler):  

        global CERTFILE
        global PRIVKEYFILE
        global CAFILE

        cert = CERTFILE
        privkey = PRIVKEYFILE
        ca = CAFILE

        def verify_cert_cb(*x):
            # SSL verification callback
            return True

        server = CherryPyWSGIServerSSL((self.host, self.port), handler, ssl_certificate=cert, ssl_private_key=privkey, ssl_ca_certificate=ca, ssl_verification_cb=verify_cert_cb, ssl_verify_peer=True, ssl_fail_no_peer_cert=False)

        server.ssl_certificate = cert
        server.ssl_private_key = privkey
        server.ssl_ca_certificate = ca

        server.certificate_verify_cb = verify_cert_cb

        try:  
            server.start()  
        finally:  
            server.stop()  
  

# Add our new MySSLCherryPy class to the supported servers  
# under the key 'mysslcherrypy'

server_names['mysslcherrypy'] = MySSLCherryPy  


# SSL-enabled server
app = Bottle()

@app.route('/cert/')
def cert():
    if request.environ['wsgi.ssl_peer_certificate'] != None:
        user_cert = request.environ['wsgi.ssl_peer_certificate'].get_subject().get_components()
        print user_cert
    else:
        print 'peer didn\'t provide certificate'
    return 'Testing string'

run(app, host='0.0.0.0', port='443', server='mysslcherrypy', debug=True)  



