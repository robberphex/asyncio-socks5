#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging

from server import Server


loop = asyncio.get_event_loop()
""":type : asyncio.AbstractEventLoop"""


def main():
    coro = loop.create_server(Server, '127.0.0.1', 1081)
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

