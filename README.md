## Python ssl http server

This is small simple http ssl-enabled server, based on bottle and cherrypy.
The key feature is that it can request user agent to authenticate itself with certificate.
Certificate validation function is fully customizable and behavior of validation could be tuned.
For example, you can decide what to do with clients, which prefered not to provide certificate.
In this case server can abort ssl handshake, or to accept that, but application will be informed about that.
This server could became very handy tool for building secured infrastructures.
