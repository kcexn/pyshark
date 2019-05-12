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
from pyshark.tshark.Tshark.tshark import TsharkProcess


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
#        self.tshark_path = tshark_path
        self._override_prefs = override_prefs
        self.debug = False
#        self.use_json = use_json
        self.include_raw = include_raw
        self._packets = []
        self._current_packet = 0
        self._display_filter = display_filter
        self._capture_filter = capture_filter
#        self._only_summaries = only_summaries
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
        self._tshark = TsharkProcess(
                use_json = use_json,
                tshark_path = tshark_path,
                only_summaries = only_summaries
        )
        if (encryption_type and
                encryption_type.lower() in
                self.SUPPORTED_ENCRYPTION_STANDARDS
                ):
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            raise UnkownEncryptionStandardException(
                'Only the following standards are supported: %s.'
                % ', '.join(self.SUPPORTED_ENCRYPTION_STANDARDS))

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
