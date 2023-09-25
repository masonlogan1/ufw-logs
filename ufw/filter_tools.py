"""
AUTHOR:     Mason Logan <ufw@masonlogan.com>
CREATED:    9-21-2023
UPDATED:    9-22-2023
COMMITTER:  Mason Logan <ufw@masonlogan.com>

Provides a set of constants that can be used as a way of filtering a
UFWLogFile object
"""
from collections.abc import Callable as abcCallable
from types import FunctionType
from typing import Callable, Any, Union


class FilterFunction(abcCallable):
    """
    Wrapper for functions returned by LogFilter that allows for logical
    combination of functions
    """

    # The goal is to provide syntax like:
    #   relevant_logs = UFWLogfile(<filename>)[(DPT==25565)&(EVENT=='BLOCK')]
    # that would allow for finding all blocked attempts at accessing port 25565
    #
    # This will allow users to create complex queries to search for specific
    # types of events in the log.
    #
    # Another possibility might be:
    #   fails = UFWLogfile(<filename>)[(EVENT=='BLOCK') & (SRC=='20.20.20.20')]
    # which would provide a list of all attempts made by someone at IP address
    # 20.20.20.20 that were rejected
    #

    def __init__(self, func):
        self.func = func

    def __call__(self, value):
        return self.func(value)

    def __and__(self, func: Callable):
        return FilterFunction(lambda value: self.func(value) and func(value))

    def __or__(self, func: Callable):
        return FilterFunction(lambda value: self.func(value) or func(value))


class LogFilter:
    def __init__(self, attr):
        self.attr = attr

    def __extract(self, event):
        # if self.attr is None, we evaluate objects exactly as they are
        return event if self.attr is None else getattr(event, self.attr)

    def __eq__(self, value) -> FilterFunction:
        return FilterFunction(lambda event: self.__extract(event) == value)

    def __ne__(self, value) -> FilterFunction:
        return FilterFunction(lambda event: self.__extract(event) != value)

    def __lt__(self, value) -> FilterFunction:
        return FilterFunction(lambda event: self.__extract(event) > value)

    def __gt__(self, value) -> FilterFunction:
        return FilterFunction(lambda event: self.__extract(event) < value)

    def __le__(self, value) -> FilterFunction:
        return FilterFunction(lambda event: self.__extract(event) >= value)

    def __ge__(self, value) -> FilterFunction:
        return FilterFunction(lambda event: self.__extract(event) <= value)

    def __setattr__(self, name, value):
        # object should not be able to change after created
        if getattr(self, 'attr', False):
            raise AttributeError(f'{self.attr.upper()} is immutable!')
        self.__dict__[name] = value


EVENT_DATETIME = LogFilter("event_datetime")
HOSTNAME = LogFilter("hostname")
UPTIME = LogFilter("uptime")
EVENT = LogFilter("event")
IN = LogFilter("IN")
OUT = LogFilter("OUT")
MAC = LogFilter("MAC")
SRC = LogFilter("SRC")
DST = LogFilter("DST")
LEN = LogFilter("LEN")
TC = LogFilter("TC")
TOS = LogFilter("TOS")
PERC = LogFilter("PERC")
TTL = LogFilter("TTL")
ID = LogFilter("ID")
PROTO = LogFilter("PROTO")
SPT = LogFilter("SPT")
DPT = LogFilter("DPT")
WINDOW = LogFilter("WINDOW")
RES = LogFilter("RES")
SYN_URGP = LogFilter("SYN_URGP")
ACK = LogFilter("ACK")
PSH = LogFilter("PSH")
