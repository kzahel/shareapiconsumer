import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.httpclient
import logging

from tornado.options import define, options
define('debug',default=True, type=bool)
define('frontend_port',default=10030, type=int)
define('haze',default='http://192.168.56.1:7000', type=str)
define('datapath',default='/home/kyle/virtualbox-shared/ktorrent', type=str)
define('ktorrent_path',default='/home/kyle/ktorrent', type=str)

tornado.options.parse_command_line()
settings = dict( (k, v.value()) for k,v in options.items() )
ioloop = tornado.ioloop.IOLoop.instance()

from handlers import IndexHandler, TestHandler

routes = [
    ('/?', IndexHandler),
    ('/test?', TestHandler),

]
application = tornado.web.Application(routes, **settings)
frontend_application = tornado.web.Application(routes, **settings)
frontend_server = tornado.httpserver.HTTPServer(frontend_application, io_loop=ioloop)
frontend_server.bind(options.frontend_port, '')
frontend_server.start()
logging.info('ioloop starting')
                               
from tests import dotest
dotest()

ioloop.start()


