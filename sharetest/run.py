import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.httpclient
import logging
import pdb

from tornado.options import define, options
define('debug',default=True, type=bool)
define('frontend_port',default=10030, type=int)
#define('haze',default='http://192.168.56.1:7000', type=str)
#define('haze',default='http://api-howler.bittorrent.com', type=str)
define('haze',default='http://api-howler.io.bittorrent.com', type=str)
define('datapath',default='/home/kyle/virtualbox-shared/ktorrent', type=str)
define('ktorrent_path',default='/home/kyle/ktorrent', type=str)
define('utserver_username',default='admin', type=str)
define('utserver_password',default='', type=str)
define('utserver_webui_port',default=8080, type=int)

tornado.options.parse_command_line()
try:
    import config_prod as config
    options.utserver_username = config.utserver_username
    options.utserver_password = config.utserver_password
except:
    logging.warn('no config.py found -- using default settings')

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
                               
import tests
tests.test_seeded_on()
#tests.check_has_torrent(ip='75.101.175.247', hash='a9e8bd84f163bf66ebef3a8abe3ad849e0cb0a4f')

ioloop.start()


