import tornado.ioloop
import tornado.iostream
import socket
import pdb
import logging
import tornado.gen
from tornado.options import define, options
define('debug',default=True, type=bool)
from tornado import gen

tornado.options.parse_command_line()

ioloop = tornado.ioloop.IOLoop.instance()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
stream = tornado.iostream.IOStream(s)

def foo():
    logging.info('woo1')
    pdb.set_trace()
    logging.info('woo2')
    response = yield tornado.gen.Task(stream.write, 'GET / HTTP/1.0\r\n\r\n')

@gen.engine
def send_request(*args):
    logging.info( 'about to send request!...' )
    stream.write('GET / HTTP/1.0\r\n\r\n', callback = (yield gen.Callback('foobar')))
    response = yield gen.Wait('foobar')
    logging.info('wrote request')
    logging.info('got response %s' % response)
    stream.read_until('\r\n\r\n', callback = (yield gen.Callback('foobar2')))
    response = yield gen.Wait('foobar2')
    logging.info('got response %s' % response)
    #response2 = yield gen.Task( stream.read_until, '\r\n\r\n' )



logging.info( 'connecting...' )
#pdb.set_trace()
stream.connect(("127.0.0.1", 9090), send_request)
ioloop.start()

