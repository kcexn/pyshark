import asyncio
import os
import threading

from pyshark.tshark.tshark import get_process_path, \
    get_tshark_display_filter_flag, \
    tshark_supports_json, \
    TSharkVersionException
from pyshark.tshark.tshark_json import packet_from_json_packet
from pyshark.tshark.tshark_xml import packet_from_xml_packet, \
    psml_structure_from_xml

class TsharkProcess():
    """ Class to encapsulate methods related to Tshark
    """

    def __init__(
            self, 
            eventloop = None,
            use_json = False,
            tshark_path = None,
            only_summaries = False
    ):
        self.use_json = use_json
        self.tshark_path = tshark_path
        self._only_summaries = only_summaries

        if eventloop is None:
            self._setup_eventloop()
        else:
            self.eventloop = eventloop
        self._tshark_process = self.eventloop.run_until_complete(
            self._get_tshark_process()
        )

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
        tshark_process = existing_process or \
            self.eventloop.run_until_complete(self._get_tshark_process())
        psml_strucutre, data = self.\
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

    async def _cleanup_subprocess(self, process):
        """
        Kill the given process and properly closes any pipes connected 
        to it.
        """
        if process.returncode is None:
            try:
                process.kill()
                return await asyncio.wait_for(process.wait(), 1)
            except concurrent.futures.TimeoutError:
                self._log.debug('Waiting for process to close failed, may have'
                                'zombie process.')
            except ProcessLookupError:
                pass
            except OSError:
                if os.name != 'nt':
                    raise
        elif process.returncode > 0:
            raise TSharkCrashException('TShark seems to have crashed '
                                       '(retcode: %d). Try rerunning in debug '
                                       'mode [capture_obj.set_debug()] or try '
                                       'updating tshark.'
                                       % process.returncode)
    # TODO: get_parameters here should be replaced by passing arguments
    # into the TsharkProcess
    async def _get_tshark_process(
            self, 
            packet_count = None, 
            stdin = None
    ):
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

    def _stderr_output(self):
        # Ignore stderr output unless in debug mode (sent to console)
        return None if self.debug else open(os.devnull, "w")

    def _get_tshark_path(self):
        return get_process_path(self.tshark_path)

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
