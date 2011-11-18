from tornado import gen
from tornado.options import options
import tornado.httpclient
import json
import pdb
import uuid
import logging
import Cookie
import os
import datetime
import subprocess
import random
import math
from hashlib import sha1
import bencode
import tornado.ioloop
import functools
ioloop = tornado.ioloop.IOLoop.instance()

hexchars = map(str,range(10)) + list('abcdef')
def randomhash():
    return ''.join([random.choice(hexchars) for _ in range(40)])

def makereq(url, **kwargs):
    url = '%s%s' % (options.haze, url)
    if 'headers' not in kwargs:
        kwargs['headers'] = {}
    if 'user' in kwargs:
        kwargs['headers']['Cookie'] = '_auth=%s' % kwargs['user'].authcookie
        del kwargs['user']

    if 'body' in kwargs:
        kwargs['method'] = 'POST'

    if 'method' in kwargs and kwargs['method'].lower() == 'post':
        kwargs['headers']['Content-Type'] = 'application/json'
    return tornado.httpclient.HTTPRequest(url, **kwargs)

def doreq(url, **kwargs):
    return gen.Task(httpclient.fetch, makereq(url, **kwargs))

httpclient = tornado.httpclient.AsyncHTTPClient()


def seed_torrent(torrentpath, hostport):
    logging.info('calling seed torrent!')
    s = subprocess.Popen(['/usr/bin/python','-m','ktorrent.serve','--startup_connect_to=%s' % hostport,'--startup_connect_torrent=%s' % torrentpath], cwd=options.ktorrent_path)
    #output = s.wait()
    #pdb.set_trace()

def create_random_torrent():
    datestr = str(datetime.datetime.now())
    torrentdatadir = os.path.join( options.datapath, datestr )
    os.mkdir( torrentdatadir )
    fo = open( os.path.join(torrentdatadir, 'testdata.txt'), 'w' )
    for _ in range(1000):
        fo.write( str(math.pi) + '\n' )
    fo.close()
    torrentfilepath = os.path.join( options.datapath, datestr + '.torrent')
    s = subprocess.Popen(['/usr/bin/createtorrent','-a','http://10.10.90.24:6688',
                          torrentdatadir,
                          torrentfilepath])
    s.wait()
    fo = open( torrentfilepath )
    infohash = sha1( bencode.bencode( bencode.bdecode( fo.read() )['info'] ) ).hexdigest()
    fo.close()
    return infohash, torrentfilepath
    

class Group(object):
    def __init__(self, data, user=None):
        self.data = data
        self.user = user
    
    @gen.engine
    def get_meta(self, callback=None):
        result = yield gen.Task( httpclient.fetch, makereq('/posts/%s' % self.data['id'], user=self.user) )
        callback(result)

    @gen.engine
    def get_comments(self, callback=None):
        result = yield gen.Task( httpclient.fetch, makereq('/posts/%s/comments' % self.data['id'], user=self.user) )
        callback(result)

    @gen.engine
    def add_member_by_email(self, email, callback=None):
        result = yield doreq('/groups/%s/members' % self.data['id'], user=self.user, body=json.dumps({'member':email}))
        logging.info(result.code)
        data = json.loads(result.body)
        logging.info('add member response %s' % data)
        callback(result)

    @gen.engine
    def post_torrent(self, callback=None):
        logging.info('creatin a random torrent')
        hash, filepath = create_random_torrent()
        logging.info('postin a torrent!')
        groupid = self.data['id']
        #hash = randomhash()
        tor_obj = { 'type': 'torrent',
                    'hash': hash,
                    'name': 'foobar',
                    'seed': True,
                    'magnet': 'magnet:?xt=urn:btih:%s' % hash,
                    'size': 1,
                    }



        result = yield gen.Task(self.user.create_post, dict(body='test torrent post',
                                                       to=[ 
                    {'type':'group', 'id':groupid},
                    {'type':'user', 'id':self.user.data['id']}
                    ],
                                                       object=tor_obj) )
        if result:
            logging.info('success creatin torrent thing')
        else:
            logging.error('error creatin torrent thing')
        
        # listen for updates ...

        hostport = '192.168.56.1:8889'
        #ioloop.add_timeout( time.time() + 5, functools.partial(seed_torrent, filepath, hostport) )


class Post(object):

    def __init__(self, data):
        self.data = data
        self._when_callback = None

    def poll_until_seeded_on(self, when_callback):
        """ keeps polling until seeded on attribute is set """

        self._when_callback = when_callback


    

class User(object):

    @classmethod
    @gen.engine
    def create(self, name, password, callback=None):
        args = { #'email':'kyle+%s@bittorrent.com' % str(uuid.uuid4()),
            'email':name,
            'password':password }
        randomkey = object()
        kwargs = { 'body': json.dumps( args ),
                   'headers': {'Content-Type':'application/json'},
                   'callback': (yield gen.Callback(randomkey)),
                   'method': 'POST'}
        httpclient.fetch("%s/user" % options.haze, **kwargs)
        response = yield gen.Wait(randomkey)
        if response.code == 200:
            callback( User(name, password) )
        else:
            callback( None )


    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.authcookie = None
        self.data = None

    @gen.engine
    def login(self, callback):
        k = object()
        httpclient.fetch('%s/login' % options.haze,
                         headers = {'Content-Type':'application/json'},
                         method = 'POST',
                         body = json.dumps( dict( name = self.name,
                                                  password = self.password ) ),
                         callback = (yield gen.Callback(k)))
        response = yield gen.Wait(k)
        if response.code == 200 and 'Set-Cookie' in response.headers:
            self.data = json.loads(response.body)
            self.authcookie = Cookie.BaseCookie(response.headers['Set-Cookie'])['_auth'].value
            callback(True)
        else:
            callback(False)


    @gen.engine
    def get_groups(self, callback):
        req = makereq('/user/groups', user=self)
        response = yield gen.Task( httpclient.fetch, req )
        if response.error:
            callback(False)
        else:
            self.groups = json.loads(response.body)
            callback(self.groups)

    @gen.engine
    def get_posts(self, callback=None):
        response = yield gen.Task( httpclient.fetch, makereq('/posts', user=self) )
        if not response.error:
            callback( json.loads(response.body) )
        else:
            callback( False )

    @gen.engine
    def create_group(self, kwargs=None, callback=None):
        if kwargs:
            groupargs = kwargs
        else:
            groupargs = dict(name='testgroup %s' % str(uuid.uuid4()))
        req = makereq('/user/groups', body=json.dumps(groupargs), user=self)
        response = yield gen.Task( httpclient.fetch, req )
        if not response.error:
            callback( json.loads(response.body) )
        else:
            callback(False)
                         
    @gen.engine
    def create_post(self, args, callback=None):
        bodyargs = args
        req = makereq('/posts', body=json.dumps(bodyargs), user=self)
        response = yield gen.Task( httpclient.fetch, req )
        if not response.error:
            callback( json.loads(response.body) )
        else:
            callback( False )

import time

USERNAME='kyle+329832983298@bittorrent.com'
PASS='pass'

@gen.engine
def dotest():
    user = User(USERNAME, PASS)
    result = yield gen.Task(user.login)

    logging.info('logged in with result %s' % result)

    if user.authcookie is None:
        logging.warn('error loggin in, creatin user')
        result = yield gen.Task( User.create, USERNAME, PASS )
        logging.info('created user with result %s' % result)
        result = yield gen.Task(user.login)
        if not user.authcookie:
            logging.error('still couldnt login')
            return

    result = yield gen.Task(user.get_groups)
    if len(user.groups) > 0:
        logging.info('had a group -- selecting the first')
        group = Group(user.groups[0], user)
        meta = yield gen.Task( group.get_meta )
    else:
        logging.error('no groups! -- creating')
        result = yield gen.Task( user.create_group )
        if result:
            group = Group( result, user )
        else:
            logging.error('couldnt create')
            return
        
    posts = yield gen.Task( user.get_posts )
    if posts is False:
        logging.error('error fetching posts')
    if len(posts) == 0:
        logging.info('no posts -- creating one')
        torrent = yield gen.Task( group.post_torrent )
    else:
        logging.info('had some posts in this group already')
        #torrent = yield gen.Task( group.post_torrent )

        random_email = 'kyle+%s@bittorrent.com' % str(int( 10000 * random.random() ))
        # create a random user
        #user = yield gen.Task( User.create, 'kyle+%s@bittorrent.com' % randomchrs, 'pass' )

        logging.info('adding member')
        yield gen.Task( group.add_member_by_email, random_email )
        logging.info('added random member')
        


    
    

