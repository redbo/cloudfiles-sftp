#!/usr/bin/python

import eventlet
eventlet.monkey_patch()

import paramiko
import cloudfiles
import mimetypes
import os
import sys
import stat
import tempfile
import ConfigParser
import SocketServer

class CloudFilesHandle(paramiko.SFTPHandle):
    def __init__(self, container, path, flags, conn):
        paramiko.SFTPHandle.__init__(self, flags)
        cont = conn.get_container(container)
        self.writefile = self.readfile = tempfile.TemporaryFile()
        self.flags = flags
        if flags & os.O_TRUNC:
            self.obj = cont.create_object(path)
            self.obj.content_type = mimetypes.guess_type(path)[0]
        else:
            self.obj = cont.get_object(path)
            self.obj.read(buffer=self.writefile)

    def close(self):
        if self.flags & os.O_RDWR or self.flags & os.O_WRONLY:
            self.writefile.seek(0)
            self.obj.write(self.writefile)
            self.writefile.seek(0)
        paramiko.SFTPHandle.close(self)

class SFTPServerInterface(paramiko.SFTPServerInterface):
    def __init__(self, server, get_conn):
        self.conn = get_conn()

    def _split_path(self, path):
        parts = path.lstrip('/').split('/', 2)
        while '' in parts:
            parts.remove('')
        return parts

    def _dir_entry(self, name):
        entry = paramiko.SFTPAttributes()
        entry.filename = name
        entry.st_size = 1024
        entry.st_mode = stat.S_IFDIR | 0755
        return entry

    def _file_entry(self, name, size):
        entry = paramiko.SFTPAttributes()
        entry.filename = name
        entry.st_size = size
        entry.st_mode = stat.S_IFREG | 0666
        return entry

    def stat(self, path):
        parts = self._split_path(path)
        if len(parts) <= 1:
            return self._dir_entry(parts and parts[-1] or '')
        else:
            return self._file_entry(parts[-1], 1024)
            #return self._dir_entry('') # TODO
    lstat = stat

    def mkdir(self, path, attr):
        parts = self._split_path(path)
        if not parts:
            return paramiko.SFTP_PERMISSION_DENIED
        for y in xrange(len(parts)):
            response = self.conn.make_request('PUT', parts[:y+1], '',
                    {'Content-Type': 'application/directory'})
            if response.status not in (201, 202):
                return paramiko.SFTP_FAILURE
            response.read()
        return paramiko.SFTP_OK

    def rmdir(self, path, attr):
        parts = self._split_path(path)
        if not parts:
            return paramiko.SFTP_PERMISSION_DENIED
        container = self.conn.get_container(parts[0])
        if container.list_objects_info(path='/'.join(parts[1:])):
            return paramiko.SFTP_PERMISSION_DENIED
        response = self.conn.make_request('DELETE', path)
        return paramiko.SFTP_OK

    def list_folder(self, path):
        parts = self._split_path(path)
        retval = []
        if not parts:
            for container in self.conn.list_containers():
                retval.append(self._dir_entry(container))
        else:
            container = self.conn.get_container(parts[0])
            for object in container.list_objects_info(path='/'.join(parts[1:])):
                parts = self._split_path(object['name'])
                while '' in parts:
                    parts.remove('')
                name = parts[-1]
                if 'application/dir' in object['content_type'] or \
                        'application/folder' in object['content_type']:
                    retval.append(self._dir_entry(name))
                else:
                    retval.append(self._file_entry(name, object['bytes']))
        return retval

    def remove(self, file):
        response = self.conn.make_request('DELETE', path)
        if response.status >= 300:
            return paramiko.SFTP_PERMISSION_DENIED
        return paramiko.SFTP_OK

    def open(self, path, flags, attr):
        parts = self._split_path(path)
        return CloudFilesHandle(parts[0], '/'.join(parts[1:]), flags, self.conn)

class Authorization(paramiko.ServerInterface):
    def __init__(self, set_connection):
        self._set_conn = set_connection

    def check_auth_password(self, username, password):
        try:
            self._set_conn(cloudfiles.get_connection(username, password))
                    # authurl='https://auth.stg.swift.racklabs.com/auth'))
            return paramiko.AUTH_SUCCESSFUL
        except:
            return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

class SFTPConnectionRequestHandler(SocketServer.BaseRequestHandler):
    def setup(self):
        self.transport = paramiko.Transport(self.request)
        self.transport.load_server_moduli()
        so = self.transport.get_security_options()
        so.digests = ('hmac-sha1',)
        so.compression = ('zlib@openssh.com', 'none')
        for key in self.server.host_keys:
            self.transport.add_server_key(key)
        self.transport.set_subsystem_handler('sftp', paramiko.SFTPServer,
            sftp_si=SFTPServerInterface, get_conn=self._get_connection)

    def handle(self):
        auth_interface = Authorization(self._set_connection)
        self.transport.start_server(server=auth_interface)
        chan = self.transport.accept(30)
        if chan is None:
            raise Exception('channel not opened (authentication failure?)')
        self.transport.join()

    def _set_connection(self, conn):
        self._connection = conn
    
    def _get_connection(self):
        return self._connection

if __name__ == '__main__':
    config = ConfigParser.RawConfigParser()
    config.read('cloudfiles_sftp.ini')
    cfgSection = 'cloudfiles_sftp'
    bind_ip = config.get(cfgSection, 'bind_ip')
    bind_port = config.getint(cfgSection, 'bind_port')
    host_keys = []
    for optname in config.options(cfgSection):
        if optname.startswith('host_key'):
            key = config.get(cfgSection, optname)
            try:
                host_key = paramiko.RSAKey.from_private_key_file(filename=key)
            except paramiko.SSHException:
                host_key = paramiko.DSSKey.from_private_key_file(filename=key)
            host_keys.append(host_key)
    if not host_keys:
        raise ValueError('no host keys configured')
    server = SocketServer.TCPServer((bind_ip, bind_port),
                                    SFTPConnectionRequestHandler)
    server.allow_reuse_address = True
    server.host_keys = host_keys
    server.serve_forever()

