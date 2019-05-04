import abc
from abc import ABC
import asyncio
import os
import subprocess
import sys
import threading
import concurrent.futures

import logbook
from logbook import StreamHandler
from pyshark.tshark.tshark import get_process_path, \
        get_tshark_display_filter_flag, \
        tshark_supports_json, \
        TSharkVersionException
from pyshark.tshark.tshark_json import packet_from_json_packet
from pyshark.tshark.tshark_xml import packet_from_xml_packet, \
        psml_structure_from_xml

class CaptureABC(ABC):
    """ Class Defining the Capture Interface 
        to be inherited by all Capture Classes

        Capture classes must be iterable.
        Capture classes must be able to retrieve parameters
    """
    DEFAULT_BATCH_SIZE = 2 ** 16
    SUMMARIES_BATCH_SIZE = 64
    DEFAULT_LOG_LEVEL = logbook.CRITICAL
    SUPPORTED_ENCRYPTION_STANDARDS = ['wep', 'wpa-pwk', 'wpa-pwd', 'wpa-psk']

    def __init__(
            self, 
            display_filter=None, 
            only_summaries=False, 
            eventloop=None,
            decryption_key=None, 
            encryption_type='wpa-pwd', 
            output_file=None,
            decode_as=None,  
            disable_protocol=None, 
            tshark_path=None,
            override_prefs=None, 
            capture_filter=None, 
            use_json=False, 
            include_raw=False,
            custom_parameters=None
        ):

        self.loaded = False
        self.tshark_path = tshark_path
        self._override_prefs = override_prefs
        self.debug = False
        self.use_json = use_json
        self.include_raw = include_raw
        self._packets = []
        self._current_packet = 0
        self._display_filter = display_filter
        self._capture_filter = capture_filter
        self._only_summaries = only_summaries
        self._output_file = output_file
        self._running_processes = set()
        self._decode_as = decode_as
        self._disable_protocol = disable_protocol
        self._log = logbook.Logger(self.__class__.__name__, 
                level=self.DEFAULT_LOG_LEVEL)
        self._closed = False
        self._custom_parameters = custom_parameters

        if include_raw and not use_json:
            raise RawMustUseJsonException('use_json must be True if \
                    include_raw')

        self.eventloop = eventloop
        if self.eventloop is None:
            self._setup_eventloop()
        if (encryption_type and 
                encryption_type.lower() in 
                self.SUPPORTED_ENCRYPTION_STANDARDS
            ):
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            raise UnknownEncyptionStandardException('Only the following \
                    standards are supported: %s.'\
                    % ', '.join(self.SUPPORTED_ENCRYPTION_STANDARDS))

    def _setup_eventloop(self):
        """
        Sets up a new eventloop as the current one according to the OS.
        """
        if os.name == 'nt':
            self.eventloop = asyncio.ProactorEventLoop()
        else:
            self.eventloop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.eventloop)
        if os.name == 'posix' and isinstance(threading.current_thread(), 
                threading._MainThread):
            asyncio.get_child_watcher().attach_loop(self.eventloop)

    def _packets_from_tshark_sync(
            self, 
            packet_count=None, 
            existing_process=None
        ):
        """
        Returns a generator of packets.
        This is the sync version of packets_from_tshark. It wait for 
        the completion of each coroutine and reimplements reading 
        packets in a sync way, yielding each packet as it arrives.
        
        :param packet_count: If given, stops after this amount of 
        packets is captured.
        """
        # NOTE: This has code duplication with the async version, 
        # think about how to solve this
        tshark_process = existing_process or \
                self.eventloop.run_until_complete(self._get_tshark_process())
        psml_structure, data = self.\
                eventloop.\
                run_until_complete(
                        self._get_psml_struct(tshark_process.stdout)
                        )
        packets_captured = 0

        data = b''
        try:
            while True:
                try:
                    packet, data = self.eventloop.run_until_complete(
                        self._get_packet_from_stream(
                            tshark_process.stdout, 
                            data, 
                            psml_structure=psml_structure,
                            got_first_packet=packets_captured > 0
                            )
                        )
                except EOFError:
                    self._log.debug('EOF reached (sync)')
                    break

                if packet:
                    packets_captured += 1
                    yield packet
                if packet_count and packets_captured >= packet_count:
                    break
        finally:
            self.eventloop.run_until_complete(
                    self._cleanup_subprocess(tshark_process)
                    )

    @abc.abstractmethod
    def __iter__():
        pass

    @abc.abstractmethod
    def get_parameters():
        pass
