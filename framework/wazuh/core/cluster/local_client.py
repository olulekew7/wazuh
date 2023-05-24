# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
import os
import time
from typing import Tuple

import uvloop

import wazuh.core.cluster.utils
from wazuh.core import common, exception
from wazuh.core.cluster import client


class LocalClientHandler(client.AbstractClient):
    """
    Handle connection with the cluster's local server.
    """

    def __init__(self, **kwargs):
        """Class constructor.

        Parameters
        ----------
        kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(**kwargs)
        self.response_available = asyncio.Event()
        self.response = b''

    def _create_cmd_handlers(self):
        """Add handlers to _cmd_handler dictionary"""
        super()._create_cmd_handlers()
        self._cmd_handler.update(
            {
                b'dapi_res': lambda _, data: self._cmd_dapi_res_or_send_f_res(data),
                b'send_f_res': lambda _, data: self._cmd_dapi_res_or_send_f_res(data),
                b'ok': lambda _, data: self._cmd_ok(data),
                b'control_res': lambda _, data: self._cmd_control_res(data),
                b'dapi_err': lambda _, data: self._cmd_dapi_err(data),
                b'err': lambda _, data: self._cmd_err(data),
            }
        )

    def connection_made(self, transport):
        """Define process of connecting to the server.

        A 'hello' command is not necessary because the local server generates a
        random name for the local client.

        Parameters
        ----------
        transport : asyncio.Transport
            Socket to write data on.
        """
        self.transport = transport

    def _cancel_all_tasks(self):
        pass

    def _cmd_dapi_res_or_send_f_res(self, data: bytes) -> Tuple[bytes, bytes]:
        """Handle incoming dapi_res_or_send_f_res requests

        Parameters
        ----------
        data : bytes
            Received payload.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.            
        """
        if data.startswith(b'Error'):
            return b'err', self.process_error_from_peer(data)
        elif data not in self.in_str:
            return b'err', self.process_error_from_peer(b'Error receiving string: ID ' + data + b' not found.')
        self.response = self.in_str[data].payload
        self.response_available.set()
        # Remove the string after using it
        self.in_str.pop(data, None)
        return b'ok', b'Distributed api response received'

    def _cmd_ok(self, data: bytes) -> Tuple[bytes, bytes]:
        """Handle incoming ok requests

        Parameters
        ----------
        data : bytes
            Received payload.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.            
        """
        if data.startswith(b'Error'):
            return b'err', self.process_error_from_peer(data)
        self.response = data
        self.response_available.set()
        return b'ok', b'Sendsync response received'

    def _cmd_control_res(self, data: bytes) -> Tuple[bytes, bytes]:
        """Handle incoming control_res requests

        Parameters
        ----------
        data : bytes
            Received payload.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.            
        """
        if data.startswith(b'Error'):
            return b'err', self.process_error_from_peer(data)
        self.response = data
        self.response_available.set()
        return b'ok', b'Response received'

    def _cmd_dapi_err(self, data: bytes) -> Tuple[bytes, bytes]:
        """Handle incoming dapi_err requests

        Parameters
        ----------
        data : bytes
            Received payload.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.            
        """
        self.response = data
        self.response_available.set()
        return b'ok', b'Response received'

    def _cmd_err(self, data: bytes) -> Tuple[bytes, bytes]:
        """Handle incoming err requests

        Parameters
        ----------
        data : bytes
            Received payload.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.            
        """
        self.response = data
        self.response_available.set()
        return b'ok', b'Error response received'

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Define commands available in a local client.

        Parameters
        ----------
        command : bytes
            Received command from client.
        data : bytes
            Received payload from client.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        self.logger.debug(f"Command received: {command}")
        return self._cmd_handler.get(command, self._command_not_found)(command, data)

    def process_error_from_peer(self, data: bytes):
        """Handle "err" response.

        Errors from the cluster come already formatted into JSON format, they can therefore be returned the same way.

        Parameters
        ----------
        data : bytes
            Error message.

        Returns
        -------
        data : bytes
            Error message in JSON format.
        """
        self.response = data
        self.response_available.set()
        return data

    def connection_lost(self, exc):
        """Mark the Future as done."""
        self.on_con_lost.set_result(True)


class LocalClient(client.AbstractClientManager):
    """
    Initialize variables, connect to the server, send a request, wait for a response and disconnect.
    """
    ASYNC_COMMANDS = [b'dapi', b'dapi_fwd', b'send_file', b'sendasync']

    def __init__(self):
        """Class constructor"""
        super().__init__(configuration=wazuh.core.cluster.utils.read_config(), enable_ssl=False, performance_test=0,
                         concurrency_test=0, file='', string=0, logger=logging.getLogger(), tag="Local Client",
                         cluster_items=wazuh.core.cluster.utils.get_cluster_items())
        self.request_result = None
        self.protocol = None
        self.transport = None

    async def start(self):
        """Connect to the server and the necessary asynchronous tasks."""
        # Get a reference to the event loop as we plan to use low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()
        try:
            self.transport, self.protocol = await loop.create_unix_connection(
                protocol_factory=lambda: LocalClientHandler(loop=loop, on_con_lost=on_con_lost,
                                                            name=self.name, logger=self.logger,
                                                            fernet_key='', manager=self,
                                                            cluster_items=self.cluster_items),
                path=os.path.join(common.WAZUH_PATH, 'queue', 'cluster', 'c-internal.sock'))
        except (ConnectionRefusedError, FileNotFoundError):
            raise exception.WazuhInternalError(3012)
        except MemoryError:
            raise exception.WazuhInternalError(1119)
        except Exception as e:
            raise exception.WazuhInternalError(3009, str(e))

    async def wait_for_response(self, timeout: int) -> str:
        """Wait for cluster response.

        Wait until response is ready. Every ['intervals']['worker']['keep_alive'] seconds, a keepalive command
        is sent to the local server so that this client is not disconnected for inactivity.

        Parameters
        ----------
        timeout : int
            Time after which an exception is raised if the response is not ready.

        Returns
        -------
        str
            Response from local server.
        """
        start_time = time.perf_counter()

        while True:
            elapsed_time = time.perf_counter() - start_time
            min_timeout = min(max(timeout - elapsed_time, 0),
                              self.cluster_items['intervals']['worker']['keep_alive'])
            try:
                await asyncio.wait_for(self.protocol.response_available.wait(), timeout=min_timeout)
                return self.protocol.response.decode()
            except asyncio.TimeoutError:
                if min_timeout < self.cluster_items['intervals']['worker']['keep_alive']:
                    raise exception.WazuhInternalError(3020)
                else:
                    try:
                        # Keepalive is sent so local server does not close communication with this client.
                        await self.protocol.send_request(b'echo-c', b'keepalive')
                    except exception.WazuhClusterError as e:
                        if e.code == 3018:
                            raise exception.WazuhInternalError(3020)
                        else:
                            raise e

    async def send_api_request(self, command: bytes, data: bytes) -> str:
        """Send DAPI request to the server and wait for response.

        Parameters
        ----------
        command : bytes
            Command to execute.
        data : bytes
            Data to send.

        Returns
        -------
        request_result : str
            Response from local server.
        """
        try:
            result = (await self.protocol.send_request(command, data)).decode()
        except exception.WazuhException as e:
            if e.code == 3020 and command in self.ASYNC_COMMANDS:
                result = str(e)
            else:
                # If a synchronous response was expected but an exception is received instead, raise it.
                raise

        if result == 'There are no connected worker nodes':
            request_result = {}
        elif command in self.ASYNC_COMMANDS or result == 'Sent request to master node':
            request_result = await self.wait_for_response(
                self.cluster_items['intervals']['communication']['timeout_dapi_request']
            )
        # If no more data is expected, immediately return send_request's output.
        else:
            request_result = result

        return request_result

    async def execute(self, command: bytes, data: bytes) -> str:
        """Execute a command in the local client.

        Manage the connection with the local_server by creating such connection. Then, after sending a request
        and receiving the response, the connection is closed.

        Parameters
        ----------
        command : bytes
            Command to execute.
        data : bytes
            Data to send.

        Returns
        -------
        result : str
            Request response.
        """
        await self.start()

        try:
            result = await self.send_api_request(command, data)
        finally:
            self.transport.close()
            await self.protocol.on_con_lost

        return result

    async def send_file(self, path: str, node_name: str = None) -> str:
        """Send a file to the local server.

        Parameters
        ----------
        path : str
            Full path to file.
        node_name : str
            Name of the destination node.

        Returns
        -------
        str
            Request response.
        """
        await self.start()
        return await self.send_api_request(b'send_file', f"{path} {node_name}".encode())
