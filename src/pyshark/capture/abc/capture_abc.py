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
            raise RawMustUseJsonException('use_json must be True if '
                                          'include_raw')

        self.eventloop = eventloop
        if self.eventloop is None:
            self._setup_eventloop()
        if (encryption_type and
                encryption_type.lower() in
                self.SUPPORTED_ENCRYPTION_STANDARDS
                ):
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            raise UnkownEncryptionStandardException(
                'Only the following standards are supported: %s.'
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

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        """
        Returns a new tshark process with previously-set parameters.
        """
        if self.use_json:
            output_type = 'json'
            if not tshark_supports_json(self.tshark_path):
                raise TSharkVersionException('JSON only supported on '
                                             'Wireshark >= 2.2.0')
        else:
            output_type = 'psml' if self._only_summaries else 'pdml'
        parameters = [self._get_tshark_path(), '-l', '-n', '-T', output_type] \
            + self.get_parameters(packet_count=packet_count)

        self._log.debug('Creating TShark subprocess with parameters: ' +
                        ' '.join(parameters))
        self._log.debug('Executable: %s' % parameters[0])
        tshark_process = await \
            asyncio.create_subprocess_exec(*parameters,
                                           stdout=subprocess.PIPE,
                                           stderr=self._stderr_output(),
                                           stdin=stdin)
        self._created_new_process(parameters, tshark_process)
        return tshark_process

    def _created_new_process(self, parameters, process, process_name="TShark"):
        self._log.debug(process_name + ' subprocess created')
        if process.returncode is not None and process.returncode != 0:
            raise TSharkCrashException(
                '{} seems to have crashed.'
                'Try updating it.'
                '(command ran: "{}")'.format(process_name,
                                             ' '.join(parameters)
                                             )
            )
        self._running_processes.add(process)

    def _get_tshark_path(self):
        return get_process_path(self.tshark_path)

    def _stderr_output(self):
        # Ignore stderr output unless in debug mode (sent to console)
        return None if self.debug else open(os.devnull, "w")

    async def _get_psml_struct(self, fd):
        """Gets the current PSML (packet summary xml) structure in a 
        tuple ((None, leftover_data)),
        only if the capture is configured to return it, else returns 
        (None, leftover_data).

        A coroutine.
        """
        data = b''
        psml_struct = None

        if self._only_summaries:
            # If summaries are read, we need the psdml structure which
            # appears on top of the file.
            while not psml_struct:
                new_data = await fd.read(self.SUMMARIES_BATCH_SIZE)
                data += new_data
                psml_struct, data = self._extract_tag_from_data(data,
                                                                b'structure')
                if psml_struct:
                    psml_struct = psml_structure_from_xml(psml_struct)
                elif not new_data:
                    return None, data
            return psml_struct, data
        else:
            return None, data

    async def _get_packet_from_stream(self,
                                      stream, existing_data,
                                      got_first_packet=True,
                                      psml_structure=None
                                      ):
        """A coroutine which returns a single packet if it can be read 
        from the given StreamReader.

        :return a tuple of (packet, remaining_data). The packet will 
        be None if there was not enough XML data to create
        a packet. remaining_data is the leftover data which was not 
        enough to create a packet from.
        :raises EOFError if EOF was reached.
        """
        # yield each packet in existing_data
        if self.use_json:
            packet, existing_data = self._extract_packet_json_from_data(
                existing_data,
                got_first_packet=got_first_packet)
        else:
            packet, existing_data = self._extract_tag_from_data(existing_data)

        if packet:
            if self.use_json:
                packet = packet_from_json_packet(packet)
            else:
                packet = packet_from_xml_packet(
                    packet, psml_structure=psml_structure)
            return packet, existing_data

        new_data = await stream.read(self.DEFAULT_BATCH_SIZE)
        existing_data += new_data

        if not new_data:
            # Reached EOF
            raise EOFError()
        return None, existing_data

    @classmethod
    def _extract_packet_json_from_data(cls, data, got_first_packet=True):
        tag_start = 0
        if not got_first_packet:
            tag_start = data.find(b"{")
            if tag_start == -1:
                return None, data
        closing_tag = cls._get_json_separator()
        tag_end = data.find(closing_tag)
        if tag_end == -1:
            closing_tag = ("}%s%s]" % (os.linesep, os.linesep)).encode()
            tag_end = data.find(closing_tag)
        if tag_end != -1:
            # Include closing parenthesis but not comma
            tag_end += len(closing_tag) - 1
            return data[tag_start:tag_end], data[tag_end + 1:]
        return None, data

    @classmethod
    def _get_json_separator(cls):
        return ("}%s%s  ," % (os.linesep, os.linesep)).encode()

    def next_packet(self):
        if self._current_packet >= len(self._packets):
            raise StopIteration()
        cur_packet = self._packets[self._current_packet]
        self._current_packet += 1
        return cur_packet

    def __getitem__(self, item):
        """
        Gets the packet in the given index.

        :param item: packet index
        :return: Packet object.
        """
        return self._packets[item]

    @abc.abstractmethod
    def __iter__(self):
        pass

    @abc.abstractmethod
    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to
        the configuration of this class.
        """
        params = []
        if self._capture_filter:
            params += ['-f', self._capture_filter]
        if self._display_filter:
            params += [get_tshark_display_filter_flag(self.tshark_path),
                       self._display_filter]
        # Raw is only enabled when JSON is also enabled.
        if self.include_raw:
            params += ["-x"]
        if packet_count:
            params += ['-c', str(packet_count)]
        if self._custom_parameters:
            for key, val in self._custom_parameters.items():
                params += [key, val]
        if all(self.encryption):
            params += ['-o',
                       'wlan.enable_decryption:TRUE',
                       '-o',
                       'uat:80211_keys:"'
                           + self.encryption[1]
                           + '","'
                           + self.encryption[0]
                           + '"'
                       ]
        if self._override_prefs:
            for preference_name, preference_value in \
                    self._override_prefs.items():
                if all(self.encryption) and preference_name in \
                        ('wlan.enable_decryption', 'uat:80211_keys'):
                    # skip if override preferences also given via
                    # --encryption options
                    continue
                params += ['-o',
                           '{0}:{1}'.format(preference_name, preference_value)]

        if self._output_file:
            params += ['-w', self._output_file]

        if self._decode_as:
            for criterion, decode_as_proto in self._decode_as.items():
                params += ['-d',
                           ','.join(
                               [criterion.strip(),
                                decode_as_proto.strip()]
                           )
                           ]

        if self._disable_protocol:
            params += ['--disable-protocol', self._disable_protocol.strip()]

        return params
