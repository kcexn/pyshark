import os
import sys

from pyshark.capture.abc.capture_abc import CaptureABC
from pyshark.tshark.tshark import get_process_path, \
    get_tshark_display_filter_flag, \
    tshark_supports_json, \
    TSharkVersionException
from pyshark.tshark.tshark_json import packet_from_json_packet
from pyshark.tshark.tshark_xml import packet_from_xml_packet, \
    psml_structure_from_xml
from pyshark.tshark.Tshark.tshark import TsharkProcess


# Define basestring as str if we're in python3.
if sys.version_info >= (3, 0):
    basestring = str


class FileCapture(CaptureABC):
    """
    A class representing a capture read from a file.
    """

    def __init__(
            self,
            input_file=None,
            keep_packets=True,
            display_filter=None,
            only_summaries=False,
            decryption_key=None,
            encryption_type='wpa-pwk',
            decode_as=None,
            disable_protocol=None,
            tshark_path=None,
            override_prefs=None,
            use_json=False,
            output_file=None,
            include_raw=False,
            eventloop=None,
            custom_parameters=None
    ):
        """
        Creates a packet capture object by reading from file.

        :param keep_packets: Whether to keep packets after reading 
        them via next(). Used to conserve memory when reading large 
        caps (can only be used along with the "lazy" option!)
        :param input_file: File path of the capture (PCAP, PCAPNG)
        :param display_filter: A display (wireshark) filter to apply 
        on the cap before reading it.
        :param only_summaries: Only produce packet summaries, much 
        faster but includes very little information.
        :param decryption_key: Optional key used to encrypt and 
        decrypt captured traffic.
        :param encryption_type: Standard of encryption used in 
        captured traffic (must be either 'WEP', 'WPA-PWD', or 
        'WPA-PWK'. Defaults to WPA-PWK).
        :param decode_as: A dictionary of {decode_criterion_string: 
        decode_as_protocol} that are used to tell tshark to decode 
        protocols in situations it wouldn't usually, for instance 
        {'tcp.port==8888': 'http'} would make it attempt to decode any 
        8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to 
        override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}.
        :param disable_protocol: Tells tshark to remove a dissector 
        for a specific protocol.
        :param use_json: Uses tshark in JSON mode (EXPERIMENTAL). 
        It is a good deal faster than XML but also has less 
        information. Available from Wireshark 2.2.0.
        :param output_file: A string of a file to write every read 
        packet into (useful when filtering).
        :param custom_parameters: A dict of custom parameters to pass 
        to tshark, i.e. {"--param": "value"}
        """
        self.input_filename = input_file
        try:
            path_exists = os.path.exists(self.input_filename)
        except TypeError:
            self.input_filename = input_file.name
            path_exists = os.path.exists(self.input_filename)
        if not path_exists:
            raise FileNotFoundError(
                    '[Errno 2] No such file or '
                    'directory: {}'.format(self.input_filename)
            )
        self.keep_packets = keep_packets
        self.__pkts = []
        self.tshark_path = tshark_path
        self.use_json = use_json
        self.only_summaries = only_summaries
        super(FileCapture, self).\
            __init__(
                display_filter=display_filter,
                only_summaries=only_summaries,
                decryption_key=decryption_key,
                encryption_type=encryption_type,
                decode_as=decode_as,
                disable_protocol=disable_protocol,
                tshark_path=tshark_path,
                override_prefs=override_prefs,
                use_json=use_json,
                output_file=output_file,
                include_raw=include_raw,
                eventloop=eventloop,
                custom_parameters=custom_parameters
        )


    def __getitem__(self, packet_index):
        # TODO: There must be a better way to conditionally 
        # overload the getitem method with user defined methods.
        if self.keep_packets:
            return self._cached_get_item(packet_index)
        else:
            return self._get_item(packet_index)

    def _cached_get_item(self, packet_index):
        if packet_index < 0:
            raise IndexError('packet index must be positive')
        if packet_index >= len(self.__pkts):
            for idx,pkt in enumerate(self):
                if len(self.__pkts) <= idx:
                    self.__pkts.append(pkt)
                if idx == packet_index:
                    return pkt
                else:
                    continue
        else:
            return self.__pkts[packet_index]
        raise IndexError('packet index out of range')

    def _get_item(self, packet_index):
        if packet_index < 0:
            raise IndexError('packet index must be positive')
        for idx,pkt in enumerate(self):
            if idx == packet_index:
                return pkt
            else:
                continue
        raise IndexError('packet index out of range')

    def get_parameters(self, packet_count=None):
        return super(FileCapture, self).\
            get_parameters(packet_count=packet_count) \
            + ['-r', self.input_filename]

    def __repr__(self):
        if self.keep_packets:
            return '<%s %s>' % (self.__class__.__name__, self.input_filename)
        else:
            return '<%s %s (%d packets)>' % (self.__class__.__name__,
                                             self.input_filename, 
                                             len(self._packets)
                                             )

    def __iter__(self):
        return FileCaptureIterator(
                self.tshark_path,
                params = self.get_parameters(),
                filename = self.input_filename,
                use_json = self.use_json,
                summaries = self.only_summaries
                )


class FileCaptureIterator():
    def __init__(self, 
            tshark,
            params, 
            filename,
            process = None,
            use_json = True,
            summaries = False):
        if process is None:
            self._tshark = TsharkProcess(
                    tshark_path = tshark,
                    only_summaries = summaries,
                    parameters = params,
                    use_json = True
                    )
        else:
            self._tshark = process
        self._packet_generator = \
                self._tshark._packets_from_tshark_sync(
                        )

    def __next__(self):
        return next(self._packet_generator)

    def __iter__(self):
        return self



