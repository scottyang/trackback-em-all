#!/usr/bin/env python

"""Trackback 'em All

A command line trackback/pingback client that

(1) Scan a list of RSS feeds with full-text
(2) Pingback or trackback all links found in the feed entries

It is useful if your blogging software does not have trackback/pingback
capability, not functioning properly, or pingback/trackback is just way too
slow at the end of posting.

It can be executed periodically. Etag in HTTP header is honoured, and it will
not send ping/trackback a page that has already been sent.

For more information, visit

    http://fucoder.com/code/trackback-em-all/

Required: Python 2.4 <http://python.org/>
Required: FeedParser <http://feedparser.org/>

Copyright (c) 2006-2007 Scott Yang <scotty@yang.id.au>

"Trackback 'em All" is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) any
later version.

"""

__author__ = 'Scott Yang <scotty@yang.id.au>'
__version__ = '0.2 $Rev$'

import sys
if sys.hexversion <= 0x2040000:
    print >> sys.stderr, """\
Error: tball.py requires minimum Python version 2.4.
"""
    sys.exit(1)

# Ensure FeedParser can be imported.
try:
    import feedparser
except ImportError:
    print >> sys.stderr, """\
Error: Cannot import Python module "feedparser".  Please download and install 
this module from the following website:

    http://feedparser.sourceforge.net/
"""
    sys.exit(1)

import Queue
import os
import pickle
import re
import threading
import time
import urllib
import urllib2
import urlparse


class ResponseProxy(object):
    def __init__(self, response):
        self.__response = response
        self.__cache = None

    def __getattr__(self, attr):
        return getattr(self.__response, attr)

    def __getitem__(self, key):
        try:
            value = self.__response.info()[key] or ''
        except KeyError:
            return ''
        else:
            if key.lower() == 'content-type':
                value = value.split(';')[0]
            return value

    def readall(self):
        if not self.__cache:
            self.__cache = self.__response.read()
        return self.__cache


def memoized1(func):
    def _decorator(*args, **kwargs):
        if not hasattr(func, 'cache'):
            func.cache = func(*args, **kwargs)
        return func.cache
    return _decorator


def add_feeds(feeds):
    logger = get_logger()
    feedlist = get_data('feeds', [])

    for feed_url in feeds:
        if feed_url not in feedlist:
            feed = feedparser.parse(feed_url)
            if feed.bozo:
                logger.warn('unable to add feed %s: %s', feed_url,
                    feed.bozo_exception)
                continue
            feedlist.append(feed_url)
            logger.info('feed added %s', feed_url)

    set_data('feeds', feedlist)


def del_feeds(feeds):
    logger = get_logger()
    feedlist = get_data('feeds')
    if feedlist:
        save = False
        for feed_url in feeds:
            try:
                feedlist.remove(feed_url)
                save = True
            except ValueError:
                pass

        if save:
            set_data('feeds', feedlist)


db_lock = threading.Lock()


def get_data(key, default=None):
    """Get the pickled data from the database."""

    dbm = get_db()
    db_lock.acquire()
    try:
        try:
            return pickle.loads(dbm[str(key)])
        except (pickle.PickleError, KeyError):
            return default
    finally:
        db_lock.release()


@memoized1
def get_db():
    import anydbm
    return anydbm.open(get_option().dbfile, 'c', 0644)


def get_default_dbfile():
    filename = os.path.splitext(os.path.basename(__file__))
    filename = os.path.join(os.environ.get('HOME', './'), 
        '.' + filename[0] + '.db')
    return os.path.abspath(filename)


def get_entry_content(entry):
    try:
        content = entry.content
    except (AttributeError, IndexError):
        try:
            return entry.summary
        except AttributeError:
            return ''
    else:
        for part in content:
            if getattr(part, 'type', '') == 'text/html':
                return getattr(part, 'value', '')

        return ''


def get_external_links(baseurl, content):
    re_quote = '"\''
    re_anchor = re.compile(r'<a\s[^>]*href=[' + re_quote + 
        ']?(https?://[^' + re_quote + '>]+)[' + re_quote + ']?[^>]*>.*?</a>', 
        re.S | re.I)

    # A list of hosts to skip, for example feedburner's tracking URL.
    re_skip = re.compile('http://('
        'feeds.feedburner.com'
        ')')

    for match in re_anchor.finditer(content):
        url = unescape(match.group(1))
        if not url.startswith(baseurl) and (not re_skip.match(url)):
            yield url 


def get_http_response(url, params=None, referer=None):
    if params:
        params = urllib.urlencode(params)

    headers = {'User-Agent': "Trackback 'em All/" + __version__}
    if referer:
        headers['Referer'] = referer
    request = urllib2.Request(url, params, headers)

    try:
        response = urllib2.urlopen(request)
    except (urllib2.URLError, urllib2.HTTPError):
        get_logger().error('Unable to download %s', url)
        return None

    return ResponseProxy(response)


@memoized1
def get_logger():
    import logging
    option = get_option()
    level = min(logging.CRITICAL, max(logging.DEBUG, logging.INFO +
        (option.quiet or 0) * 10 - (option.verbose or 0) * 10))

    logging.basicConfig()
    logger = logging.getLogger('trackback')
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s: %(message)s', '%b %d %H:%M:%S'))
    logger.addHandler(handler)
    logger.propagate = False

    return logger


@memoized1
def get_option():
    from optparse import OptionParser
    
    parser = OptionParser()
    parser.set_defaults(dbfile=get_default_dbfile(), thread=1)
    parser.add_option('-d', '--dbfile', action='store', dest='dbfile',
        help='Database file. Default=%default', metavar='FILE')
    parser.add_option('-q', action='count', dest='quiet',
        help='Be quieter in output')
    parser.add_option('-v', action='count', dest='verbose',
        help='Be more verbose in output')
    parser.add_option('-p', '--pretend', action='store_true', dest='pretend',
        help='Pretend mode, no actual trackback/pingback')
    parser.add_option('-t', '--thread', action='store', dest='thread',
        help='Number of concurrent threads. Default=%default', type='int')
    parser.add_option('-A', '--add', action='append', dest='feed_add',
        help='Add feed', metavar='URL')
    parser.add_option('-D', '--del', action='append', dest='feed_del',
        help='Delete feed', metavar='URL')
    parser.add_option('-L', '--list', action='store_true', dest='feed_list',
        help='List all feeds')

    options, args = parser.parse_args()

    return options


def get_pingback_url(response):
    re_pingback = re.compile(r'<link\s+rel="pingback"\s+href="([^"]+)"\s*/?>')

    pingback = response['X-Pingback']
    if pingback:
        return pingback

    ctype = response['Content-Type']
    if (ctype == 'text/html') or ctype.startswith('application/xhtml'):
        match = re_pingback.search(response.readall())
        if match:
            return unescape(match.group(1))


def get_trackback_excerpt(url, content):
    """Extract an excerpt from HTML content.

    It takes an URL and a piece of HTML document, and try to extract the
    paragraph around the URL link. The algorithm is taking from WordPress'
    pingback function in <wordpress>/xmlrpc.php

    """
    class sub_callback(object):
        re_quote = '"\''
        re_href = re.compile('href=[' + re_quote + ']?([^' + re_quote + '>]+)')

        def __init__(self):
            self.state = 0

        def __call__(self, match):
            tag = match.group(1).lower()
            if tag == 'a':
                href = self.re_href.search(match.group(0))
                if href:
                    if unescape(href.group(1)) == url:
                        self.state = 1
                        return '<a>'
                self.state = 0
            elif tag == '/a':
                if self.state:
                    self.state = 0
                    return '</a>'
            elif tag in blocks:
                return '\n\n'
            return ''

    blocks = set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'th', 'td', 'li',
        'dt', 'dd', 'pre', 'caption', 'input', 'textarea', 'button', 'body'])
    content = re.sub('\s+', ' ', content)
    content = re.sub(r'<(/?\w+).*?>', sub_callback(), content).strip()
    content = content.split('\n\n')

    for para in content:
        context = re.search('<a>(.*?)</a>', para)
        if context:
            context = re.escape(context.group(1))
            excerpt = re.sub('<.*?>', '', para).strip()
            excerpt = re.sub(r'.*?\s(.{0,100}' + context + r'.{0,100})\s.*', 
                r'\1', excerpt)

            return '[...] ' + excerpt + ' [...]'

    return re.sub(r'^(.{0,200})\s.*', r'\1', content[0]) + ' [...]'


def get_trackback_url(response):
    ctype = response['Content-Type']
    if (ctype != 'text/html') and (not ctype.startswith('application/xhtml')):
        return None

    re_rdf = re.compile(r'<rdf:RDF.*?</rdf:RDF>', re.S)
    re_identifier = re.compile('dc:identifier="([^"]+)"')
    re_trackback = re.compile('trackback:ping="([^"]+)"')

    content = response.readall()

    idx = 0
    url = response.geturl()
    while True:
        match = re_rdf.search(content, idx)
        if not match:
            break

        idx = match.end()
        rdf = match.group(0)
        
        identifier = re_identifier.search(rdf)
        if identifier and unescape(identifier.group(1)) == url:
            trackback = re_trackback.search(rdf)
            if trackback:
                return trackback.group(1)


def list_feeds():
    feedlist = get_data('feeds', [])
    feedlist.sort()
    for feed in feedlist:
        print feed


def main():
    # HACK: We are forcing the system unicode encoding to be UTF8 as it is the
    # post comment encoding amongst blogs.
    reload(sys)
    sys.setdefaultencoding('utf8')

    option = get_option()
    if option.feed_add or option.feed_del or option.feed_list:
        if option.feed_add:
            add_feeds(option.feed_add)
        if option.feed_del:
            del_feeds(option.feed_del)
        if option.feed_list:
            list_feeds()
    else:
        process_all()


def process_all():
    """Main function to process all the feeds.

    This function loads all the feed URLs from the database, fetch all the
    feeds and process all the entries. It can also optionally process them in
    parallel to reduce wait on network IO, if -t|--thread is greater than 1.

    """
    feeds = get_data('feeds', [])
    count = min(get_option().thread, len(feeds))

    if not feeds:
        return
    elif count <= 1:
        for feed in feeds:
            process_feed(feed)
    else:
        queue = Queue.Queue(len(feeds))
        for feed in feeds:
            queue.put(feed)

        threads = []
        for thread in xrange(count):
            thread = threading.Thread(target=process_thread, args=(queue, ))
            thread.setDaemon(True)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()


def process_entry(feed, entry):
    """Process Feed Item.

    It takes a feed and an entry value (from feedparser), and try to trackback
    or pingback all the URLs in the entry.

    """
    try:
        from hashlib import md5
    except ImportError:
        from md5 import new as md5

    option = get_option()
    logger = get_logger()

    entrymeta = get_data('entry:%s' % entry.link, {})

    content = get_entry_content(entry)
    contentmd5 = md5(content).hexdigest()
    if entrymeta.get('md5') == contentmd5:
        logger.debug('skip entry %s', entry.link)
        return
    entrymeta.update({'md5': contentmd5, 'time': time.time()})

    logger.info('process entry %s', entry.link)
    linksmeta = entrymeta.setdefault('links', {})

    for url in get_external_links(feed.feed.link, content):
        if url in linksmeta:
            logger.debug('skip external link %s', url)
            continue

        logger.info('check external link %s', url)
        response = get_http_response(url, referer=entry.link)
        if not response:
            continue

        # Check for Pingback first as it is lighter on our side.
        success = False
        pburl = get_pingback_url(response)
        if pburl:
            logger.warn('send pingback %s', pburl)
            if not option.pretend:
                success = send_pingback(pburl, entry.link, url)
        else:
            # Check for trackback.
            tburl = get_trackback_url(response)
            if tburl:
                logger.warn('send trackback %s', tburl) 
                if not option.pretend:
                    success = send_trackback(tburl, entry.link, entry.title,
                        get_trackback_excerpt(url, content), feed.feed.title)

        linksmeta[url] = success

    set_data('entry:%s' % entry.link, entrymeta)


def process_feed(feed_url):
    feedmeta = get_data('feed:%s' % feed_url, {})
    feed = feedparser.parse(feed_url, etag=feedmeta.get('etag'))
    if feed.get('status') == 304:
        get_logger().info('skip unmodified feed %s', feed_url)
    elif feed.bozo:
        get_logger().warn('error feed %s: %s', feed_url, 
            feed.bozo_exception)
    else:
        if feed.etag:
            feedmeta['etag'] = feed.etag
        feedmeta['time'] = time.time()
        set_data('feed:%s' % feed_url, feedmeta)

        get_logger().info('process feed %s', feed.feed.link)
        for entry in feed.entries:
            process_entry(feed, entry)


def process_thread(queue):
    get_logger().info('Thread started')
    while True:
        try:
            feed = queue.get(False)
        except Queue.Empty:
            break
        else:
            process_feed(feed)


def send_pingback(pburl, source, target):
    import xmlrpclib
    logger = get_logger()
    rpc = xmlrpclib.ServerProxy(pburl)
    try:
        msg = rpc.pingback.ping(source, target)
    except xmlrpclib.Fault, ex:
        logger.warn('pingback fault: %s %s', ex.faultCode, ex.faultString)
        return False
    except:
        logger.exception('Uncaught exception from ping server')
        return False
    else:
        logger.info('pingback success: %s', msg)
        return True


def send_trackback(tburl, url, title=None, excerpt=None, blog_name=None):
    params = {'url': url}
    if title:
        params['title'] = title
    if excerpt:
        params['excerpt'] = excerpt
    if blog_name:
        params['blog_name'] = blog_name

    result = get_http_response(tburl, params, referer=url)
    if result:
        result = result.readall()
        error = re.search(r'<error>(\d+)</error>', result)
        message = re.search(r'<message>(.*?)</message>', result)
        message = message and message.group(1) or ''
        if error:
            error = int(error.group(1))
        else:
            error = 1

        if error > 0:
            get_logger().warn('trackback response: %d %s', error, message)
        else:
            get_logger().info('trackback response: %d %s', error, message)
        return error == 0

    return False


def set_data(key, val):
    """Set pickled data from the database."""

    dbm = get_db()
    db_lock.acquire()
    try:
        dbm[str(key)] = pickle.dumps(val)
    finally:
        db_lock.release()
    return val


def unescape(url):
    """Remove XML entity from the URL"""
    url = url.replace('&amp;', '&')
    url = url.replace('&gt;', '>')
    url = url.replace('&lt;', '<')
    return url


if __name__ == '__main__':
    main()
