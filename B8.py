#!/usr/bin/env python

import os
import platform
import re
import base64
import random
import string
import socket
import pymssql
import pymysql
import smtplib
import datetime

import dns.resolver
import requests
from bs4 import BeautifulSoup
import unicodecsv


class B8Database:
    """
        Database class for MySQL and MsSQL
        apt-get install freetds-dev
        pip install pymssql
        pip install pymysql
    """

    def __init__(self, dbtype, dbhost, dbuser, dbpass, dbdatabase, dbport=None):
        dport = None

        if dbport is None:
            if dbtype == "mysql":
                dport = 3306
            elif dbtype == "mssql":
                dport = 1433
        else:
            dport = dbport

        self.dbtype = dbtype
        self.conn = self.connect(dbhost, dbuser, dbpass, dbdatabase, dport)

    def connect(self, dbhost, dbuser, dbpass, dbdatabase, dbport):
        if self.dbtype == "mysql":
            return pymysql.connect(host=dbhost, port=dbport, user=dbuser, passwd=dbpass, db=dbdatabase)
        elif self.dbtype == "mssql":
            return pymssql.connect(host=dbhost, port=dbport, user=dbuser, password=dbpass, database=dbdatabase)

    def select(self, query, values=None, fetchone=False, dictmode=True):
        if self.dbtype == "mysql":
            if dictmode:
                cursor = self.conn.cursor(pymysql.cursors.DictCursor)
            else:
                cursor = self.conn.cursor()
        elif self.dbtype == "mssql":
            if dictmode:
                cursor = self.conn.cursor(as_dict=True)
            else:
                cursor = self.conn.cursor()

        if values is not None:
            cursor.execute(query, values)
        else:
            cursor.execute(query)

        if fetchone:
            return cursor.fetchone()
        else:
            return cursor.fetchall()
        cursor.close()

    def insert(self, table, dict):
        cursor = self.conn.cursor()

        data = ()
        for dt in dict.values():
            data = data + (dt,)

        cursor.execute(self.compose(table, dict), data)

        self.conn.commit()
        cursor.close()

    def update(self, table, dict, where, values=None):
        cursor = self.conn.cursor()

        data = ()
        for dt in dict.values():
            data = data + (dt,)
        if values is not None:
            data = data + values

        cursor.execute(self.ucompose(table, dict, where), data)

        self.conn.commit()
        cursor.close()

    def delete(self, table, where=None, values=None):
        cursor = self.conn.cursor()

        query = "DELETE FROM " + table
        if where is not None:
            query = query + " WHERE " + where

        if values is not None:
            cursor.execute(query, values)
        else:
            cursor.execute(query)

        self.conn.commit()
        cursor.close()

    def close(self):
        self.conn.close()

    def compose(self, table, dict):
        keys = tuple(dict.keys())
        kstr = '(' + ', '.join(dict.keys()) + ')'

        slist = ['%s' for i in range(len(keys))]
        stlist = '(' + ', '.join(slist) + ')'

        return "INSERT INTO " + table + " " + kstr + " VALUES " + stlist

    def ucompose(self, table, dict, where):
        kstr = ', '.join([i + '=%s' for i in dict.keys()])

        return "UPDATE " + table + " SET " + kstr + " WHERE " + where

    def tablehash(self, table, field):
        result = True
        while result:
            hsh = base64.urlsafe_b64encode(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(50)))[:12]
            result = self.select("SELECT " + field + " FROM " + table + " WHERE " + field + "=%s", (hsh,), True)

        return hsh

    def field_exists(self, table, field, value):
        return self.select("SELECT " + field + " FROM " + table + " WHERE " + field + "=%s", (value,), True)

    def set_datetime(self):
        return datetime.datetime.now()


class B8Logs:
    """
        Record Logs to File
    """

    def __init__(self, path, winnewline=False):
        self.logfile = open(path, "a")
        self.newline = '\n'
        if winnewline:
            self.newline = '\r\n'

    def write(self, msg):
        self.logfile.write(msg + self.newline)

    def close(self):
        self.logfile.close()


class B8Networking:
    """
        Helper functions for network connections
        pip install requests
        pip install dnspython
    """

    def ping(self, host):
        ping_str = "-n 1" if platform.system().lower() == "windows" else "-c 1"

        if os.system("ping " + ping_str + " " + host) == 0:
            return True

        return False

    def online_web(self, host):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((host, 80))
        except socket.error:
            try:
                s.connect((host, 443))
            except:
                s.close()
                return False

        s.close()

        return True

    def online_dns(self, host):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((host, 53))
        except socket.error:
            s.close()
            return False

        s.close()

        return True

    def online_proxy(self, host):
        ports = (3128, 8080, 8888, 6588)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)

        ret = []

        for port in ports:
            try:
                s.connect((host, port))
                ret.append(port)
            except socket.error:
                continue

        s.close()

        return ret

    def lookup_domain(self, host):
        try:
            return socket.gethostbyaddr(host)[0]
        except:
            return ''

    def lookup_ip(self, host):
        host = re.sub(r'http://', '', host, re.IGNORECASE)
        host = re.sub(r'https://', '', host, re.IGNORECASE)
        host = re.sub(r'/.*$', '', host)
        try:
            return socket.gethostbyname(host)
        except:
            return False

    def lookup_dns(self, host, server=None):
        resolv = dns.resolver.Resolver()

        if server is not None:
            resolv.nameservers = [server]

        try:
            resp = resolv.query(host).response.answer[0]
            res = re.findall("IN\sA\s(.*?\..*?\..*?\..*)", str(resp))
        except:
            return []

        return [x for x in res]

    def pageup(self, link):
        try:
            code = requests.get(link).status_code
        except:
            return False

        if code == 200:
            return True

        return False

    def get_sourcecode(self, link):
        try:
            source = requests.get(link).text
        except:
            return False

        return source

    def get_headers(self, link):
        try:
            hd = requests.get(link).headers
        except:
            return False

        return hd

    def get_file(self, link, path, binary=False):
        try:
            fl = requests.get(link, stream=True)
        except:
            return False

        mode = "w"
        if binary:
            mode += "b"

        try:
            pt = open(path, mode)
            pt.write(fl.content)
            pt.close()
            return True
        except:
            return False

    def find_strings_in_url(self, strings, link):
        rate = 0

        url = self.get_sourcecode(link)
        if not url:
            return 0
        url = self.strip_tags(url)

        for line in strings:
            line = re.sub(r'\s*', '', line)
            if re.search(r'%s' % line, url, re.IGNORECASE):
                rate += 1

        return int(float(rate) / len(strings) * 100)

    def is_ip(self, ip):
        try:
            socket.inet_aton(ip)
        except socket.error:
            return False

        return True

    def is_url(self, url):
        if re.match(r'https?://.*?\..*?\..+', url, re.IGNORECASE):
            return True

        return False

    def strip_tags(self, text):
        tag_re = re.compile(r'<[^>]+>')

        return tag_re.sub('', text)

    def dir_search(self, host, pylocation, dirsearch, wordlist):
        """
         Requires dirs3arch for python 2.7
         Location: include/dirsearch
        """

        links = os.popen(pylocation + " " + dirsearch + " -u " + host + " -e php,html -w " + wordlist + " -r").read()

        plinks = re.findall('\[.*?\].*?-.*?-\s(.*?)\x1b', links)
        return ['http://' + host + x for x in plinks]

    def capture_screen(self, wkhtml, link, localfile):
        """
         Requires wkhtmltopdf
         http://wkhtmltopdf.org/downloads.html
         usage: wkhtmltoimage http://url image.png
        """

        return os.popen(wkhtml + " " + link + " " + localfile).read()


class B8Scraping:
    """
    Website scraping
    pip install beautifulsoup4
    """

    def __init__(self, source):
        self.soup = BeautifulSoup(source, 'html.parser')

    def sourcecode(self):
        return self.soup.prettify()

    def find_all(self, tag):
        return self.soup.find_all(tag)

    def find(self, tag):
        return self.soup.find(tag)

    def tag_find_all(self, tag, match):
        return tag.find_all(match)

    def tag_find(self, tag, match):
        return tag.find(match)

    def tag_getstring(self, tag):
        return tag.string


class B8Csv:
    """
    Class for creating, viewing, and editing CSV files
    pip install unicodecsv
    """

    def __init__(self, path, append=False):
        self.csv = None
        if not append:
            self.mode = 'w+b'
        else:
            self.mode = 'ab'
        self.file = open(path, self.mode)

    def read(self):
        self.csv = unicodecsv.reader(self.file)

    def write(self):
        self.csv = unicodecsv.writer(self.file)

    def writerow(self, txt):
        self.csv.writerow(txt)

    def close(self):
        self.file.close()


class B8Mail:
    """
    Class for sending emails
    """

    def __init__(self, server, port, user, passwd, ssl=False):
        if ssl:
            self.server = smtplib.SMTP_SSL(server, port)
        else:
            self.server = smtplib.SMTP(server, port)
        self.server.ehlo()
        if not ssl:
            self.server.starttls()
        self.server.login(user, passwd)

    def send(self, from_addr, to_addr, subject, msg):
        to = to_addr if type(to_addr) is list else [to_addr]

        body = "From: %s\nTo: %s\nSubject: %s\n\n%s" % (from_addr, ','.join(to), subject, msg)

        self.server.sendmail(from_addr, to_addr, body)

    def quit(self):
        self.server.quit()

