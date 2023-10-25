import json
import os
import re
from collections.abc import Iterable, Callable
from datetime import datetime

UBUNTU_LOG_PATH = '/var/log/'
UBUNTU_DEFAULT_PATH = '/var/log/ufw.log'
UFW_LOG_PATTERN = '^ufw.*'


class UFWLogFileJSONEncoder(json.JSONEncoder):
    """JSON Encoder that extracts data from a UFWLogFile object into
    JSON format"""
    def get_UFWLogEntry_json(self, ufw_entry) -> dict:
        """Extracts values from a UFWLogEntry object into a dict,
        excluding any key-value pairs where the value is None"""
        data = {
            'event_datetime': ufw_entry.event_datetime.strftime(
                '%Y-%m-%d %H:%M:%S.%f'),
            'hostname': ufw_entry.hostname,
            'uptime': ufw_entry.uptime,
            'event': ufw_entry.event,
            'IN': ufw_entry.IN,
            'OUT': ufw_entry.OUT,
            'MAC': ufw_entry.MAC,
            'SRC': ufw_entry.SRC,
            'DST': ufw_entry.DST,
            'LEN': ufw_entry.LEN,
            'TC': ufw_entry.TC,
            'TOS': ufw_entry.TOS,
            'PERC': ufw_entry.PERC,
            'TTL': ufw_entry.TTL,
            'ID': ufw_entry.ID,
            'PROTO': ufw_entry.PROTO,
            'SPT': ufw_entry.SPT,
            'DPT': ufw_entry.DPT,
            'WINDOW': ufw_entry.WINDOW,
            'RES': ufw_entry.RES,
            'SYN_URGP': ufw_entry.SYN_URGP,
            'ACK': ufw_entry.ACK,
            'PSH': ufw_entry.PSH,
        }
        return {key: value for key, value in data.items() if value is not None}

    def default(self, ufw_file_obj):
        return [self.get_UFWLogEntry_json(entry)
                for entry in ufw_file_obj.log_events]


class UFWLogEntry:
    """Class for working with a single entry in a ufw log"""

    def __init__(self, event_datetime: datetime, hostname: str, uptime: float,
                 event, IN=None, OUT=None, MAC=None, SRC=None, DST=None,
                 TC=None, LEN=None, TOS=None, PERC=None, TTL=None, ID=None,
                 PROTO=None, SPT=None, DPT=None, WINDOW=None, RES=None,
                 SYN_URGP=None, ACK=False, PSH=False, *args, **kwargs):
        self.event_datetime = event_datetime
        self.hostname = hostname
        self.uptime = uptime
        self.event = event
        self.IN = IN
        self.OUT = OUT
        self.MAC = MAC
        self.SRC = SRC
        self.DST = DST
        self.LEN = LEN
        self.TC = TC
        self.TOS = TOS
        self.PERC = PERC
        self.TTL = TTL
        self.ID = ID
        self.PROTO = PROTO
        self.SPT = SPT if not isinstance(SPT, str) else int(SPT)
        self.DPT = DPT if not isinstance(DPT, str) else int(DPT)
        self.WINDOW = WINDOW
        self.RES = RES
        self.SYN_URGP = SYN_URGP
        self.ACK = ACK
        self.PSH = PSH

    @staticmethod
    def from_str(data):
        # UFW pads the uptime timestamp with whitespace, so we have to
        # check for that and remove it or the parsing fails
        if '[ ' in data:
            data = '['.join(i.lstrip() for i in data.split('['))
        data = data.split(' ')[:-1]
        event_datetime = datetime.strptime(
            ' '.join(data[0:3]), '%b %d %H:%M:%S'
        )
        hostname = ' '.join(data[3:5])
        if not data[5][1:-1]:
            print('pause!')
        uptime = float(data[5][1:-1])
        event = data[7][:-1]
        kwargs_raw = (dat.split('=') for dat in data[8:] if '=' in dat)
        kwargs = {key: value for key, value in kwargs_raw if key and value}
        kwargs['ACK'] = 'ACK' in data[8:]
        kwargs['PSH'] = 'PSH' in data[8:]

        return UFWLogEntry(event_datetime=event_datetime, hostname=hostname,
                           uptime=uptime, event=event, **kwargs)


class UFWLogFile:
    """Class for working with ufw log files. Provides support for using as
    an iterable, context manager, and ability to mix indexes, slices, and
    functions to get log entries"""

    def __init__(self, filename=UBUNTU_DEFAULT_PATH):
        self.log_events = list()
        self.filename = filename
        with open(filename, 'r') as reader:
            for line in reader.readlines():
                self.log_events.append(UFWLogEntry.from_str(line))
        for event in self.log_events:
            event.event_datetime = event.event_datetime.replace(
                datetime.fromtimestamp(os.path.getctime(filename)).year
            )

    def search(self, search_fns: Iterable = ()):
        return [event for event in self.log_events
                if all(fn(event) for fn in search_fns)]

    def serialize_to_file(self, filename):
        with open(filename, 'w') as writer:
            json.dump(self, writer, cls=UFWLogFileJSONEncoder)

    def __getitem__(self, indexes):
        out = list()
        indexes = indexes if isinstance(indexes, Iterable) else [indexes]
        for index in indexes:
            if isinstance(index, int):
                out += [self.log_events[index]]
            if isinstance(index, slice):
                out += self.log_events[index]
            if isinstance(index, Callable):
                out += self.search([index])
            if isinstance(index, list) and all([isinstance(item, Callable)
                                                or isinstance(item, Callable)
                                                for item in index]):
                out += self.search(index)
        return out

    def __iter__(self):
        # if we already have the log events, send them
        for event in self.log_events:
            yield event

    def __enter__(self):
        # Sometimes these objects can take up a lot of memory, it may be
        # useful to use the object as a context manager so it self-destructs
        # after doing a search on a large archived file
        return self

    def __exit__(self, *args, **kwargs):
        # erases the list to ensure memory is freed
        self.log_events = list()


def filenames_by_pattern(path: str = UBUNTU_LOG_PATH, pattern=UFW_LOG_PATTERN):
    return [f'{path}{filepath}' for filepath in os.listdir(path)
            if re.match(pattern, filepath)]
