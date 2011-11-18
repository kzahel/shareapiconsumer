import tornado.web
import tornado.gen
import json
from tornado.options import options
import uuid
from tornado.gen import Task

httpclient = tornado.httpclient.AsyncHTTPClient()



class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        pass

class TestHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self):
        args = { #'email':'kyle+%s@bittorrent.com' % str(uuid.uuid4()),
            'email':'kyle@bittorrent.com',
            'password':'pass' }
        kwargs = { 'body': json.dumps( args ),
                   'headers': {'Content-Type':'application/json'},
                   'method': 'POST'}
        response = yield Task(httpclient.fetch, "%s/user" % options.haze, **kwargs)
        self.write('BAM!!!')


