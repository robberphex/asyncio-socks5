#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging

import struct

from exception import NotRecognizeProtocolException

METHOD_NOAUTH = b'\x00'
METHOD_USER = b'\x02'
METHOD_NOAC = b'\xFF'


@asyncio.coroutine
def handle_echo(reader, writer):
    hello_data = yield from reader.read(2)
    var, nmethods = struct.unpack('!BB', hello_data)
    print(var, nmethods)
    if var != 5:
        raise NotRecognizeProtocolException('Cannot recognize the protocol!')
    methods = []
    for i in range(nmethods):
        method = yield from reader.read(1)
        methods.append(method)
    method = METHOD_NOAC
    if METHOD_USER in methods:
        method = METHOD_USER
    elif METHOD_NOAUTH in methods:
        method = METHOD_NOAUTH

    data_s = b'\05' + method
    print(writer)
    yield from writer.write(data_s)
    if method == METHOD_USER:
        data = yield reader.read(2)
        ver, ulen = struct.unpack('!BB', data)
        print(ver, ulen)

    writer.close()


loop = asyncio.get_event_loop()
""":type : asyncio.AbstractEventLoop"""


def main():
    coro = asyncio.start_server(handle_echo, '127.0.0.1', 10801, loop=loop)
    server = loop.run_until_complete(coro)
    logging.info('serving on {}'.format(server.sockets[0].getsockname()))

    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
