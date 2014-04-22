#  find_times.py - Copyright (C) 2014  504ENSICS Labs
#  Sniffs out embedded timestamps in Windows registry files.
#  Developers: Andrew Case, Jerry Stormo, Joseph Sylve, and Vico Marziale
#  www.504ensics.com
#
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.


from calendar import isleap
import inspect
import os
import re
import struct
import sys
import uuid

import datetime as dt
import pyregf


DEBUG = False


def debug(msg):
    if DEBUG:
        orginStack = inspect.stack()[1]
        orginMod = orginStack[1]
        orginLine = orginStack[2]
        orginFunc = orginStack[3]
        sys.stderr.write('<%s  Ln:%i  %s>  %s\n' % (orginMod, orginLine, orginFunc, msg))


def find_epoch(data):
    fmts = [">i", "<i"]
    for i in xrange(len(data)):
        for fmt in fmts:
            try:
                intval = struct.unpack(fmt, data[i:i + 4])[0]
                ts = dt.datetime.utcfromtimestamp(intval)
                yield i, ts
            except (struct.error, ValueError):
                continue


def find_uuid(data):
    for i in xrange(len(data)):
        try:
            ts_uuid = uuid.UUID(bytes=data[i:i + 16])
            uuid1time = ts_uuid.time
            ts = dt.datetime.utcfromtimestamp((uuid1time - 0x01b21dd213814000L) * 100 / 1e9)
            yield i, ts
        except ValueError:
            continue


def find_dosdatetime(data):
    for i in xrange(len(data)):
        try:
            tdate, ttime = struct.unpack("<HH", data[i:i + 4])
            secs = (ttime & 0x1F) * 2
            mins = (ttime & 0x7E0) >> 5
            hours = (ttime & 0xF800) >> 11

            day = tdate & 0x1F
            month = (tdate & 0x1E0) >> 5
            year = ((tdate & 0xFE00) >> 9) + 1980
            try:
                ts = dt.datetime(year, month, day, hours, mins, secs)
            except ValueError:
                try:
                    ts = dt.datetime(year, month, day)
                except ValueError:
                    continue
            yield i, ts
        except struct.error:
            continue


TICKS_PER_MIN = 600000000
TICKS_PER_SEC = 10000000
TICKS_PER_MSEC = 10000
SECS_PER_DAY = 86400
SECS_PER_HOUR = 3600
SECS_PER_MIN = 60
MINS_PER_HOUR = 60
HOURS_PER_DAY = 24
EPOCH_WEEKDAY = 1
EPOCH_YEAR = 1601
DAYS_PER_NORMAL_YEAR = 365
DAYS_PER_LEAP_YEAR = 366
MONTHS_PER_YEAR = 12
_YearLengths = [DAYS_PER_NORMAL_YEAR, DAYS_PER_LEAP_YEAR]
_MonthLengths = [
    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
    [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
]


def parse_systemtime(timestamp):
    milli_secs = 0xFFFF & ((timestamp % TICKS_PER_SEC) // TICKS_PER_MSEC)
    timestamp = timestamp // TICKS_PER_SEC

    days = timestamp // SECS_PER_DAY
    seconds_in_day = timestamp % SECS_PER_DAY

    while seconds_in_day < 0:
        seconds_in_day += SECS_PER_DAY
        days -= 1
    # end while

    while seconds_in_day >= SECS_PER_DAY:
        seconds_in_day -= SECS_PER_DAY
        days += 1
    # end while

    hours = 0xFFFF & (seconds_in_day // SECS_PER_HOUR)
    seconds_in_day = seconds_in_day % SECS_PER_HOUR
    mins = 0xFFFF & (seconds_in_day // SECS_PER_MIN)
    secs = 0xFF & (seconds_in_day % SECS_PER_MIN)

    year = EPOCH_YEAR
    year += days // DAYS_PER_LEAP_YEAR

    year_temp = year - 1
    days_since_epoch = (
        (year_temp * DAYS_PER_NORMAL_YEAR) + (year_temp // 4) -
        (year_temp // 100) + (year_temp // 400)
    )

    epoch_temp = EPOCH_YEAR - 1
    days_since_epoch -= (
        (epoch_temp * DAYS_PER_NORMAL_YEAR) + (epoch_temp // 4) -
        (epoch_temp // 100) + (epoch_temp // 400)
    )

    days -= days_since_epoch
    while 1:
        leap_year = isleap(year)
        if days < _YearLengths[leap_year]:
            break
        # end if

        year += 1
        days -= _YearLengths[leap_year]
    # end while

    leap_year = isleap(year)
    months = _MonthLengths[leap_year]
    month = 0
    while days >= months[month]:
        days -= months[month]
        month += 1
    # end while

    month += 1
    days += 1

    try:
        ret = dt.datetime(year, month, days, hours, mins, secs, milli_secs * 1000)
    except ValueError:
        ret = None
    return ret


def find_systemtime(data):
    for i in xrange(len(data)):
        try:
            intval = struct.unpack("<Q", data[i:i + 8])[0]
            ts = parse_systemtime(intval)
            if ts is not None:
                yield i, ts
        except struct.error:
            continue


def find_filetime(data):  # Done
    fmts = [">Q", "<Q"]
    for i in xrange(len(data)):
        for fmt in fmts:
            try:
                # get the 64bit windows filetime (offset from year 1601)
                # convert to unix epoch time (offset from year 1970)
                intval = struct.unpack(fmt, data[i:i + 8])[0]
                toepoch = (intval - 116444736000000000) // 10000000
                ts = dt.datetime.utcfromtimestamp(toepoch)
                yield i, ts
            except (struct.error, ValueError):
                continue


'''
str_regex_short: represents short date formats of the type MM/DD/YY variations include 2 digit year up to a
    4 digit year, no guarantees on the positioning of M D Y in regex groups. Intended to feed the grouped data
    to the date constructor in all the possible combinations that make sense.

str_regex_long: represents long format datestamps. Trying for  "Month Day, Year" with this including abbreviations
    for months. Since we're looking at actual text here, should do it case insensitive.
'''
str_regex_short = re.compile(r'(\d{1,4})(?P<delim>-|/)(\d{1,2})(?P=delim)(\d{1,4})')
str_regex_long = re.compile(r'(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june|july|aug(?:ust)?|sept(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?\s(\d{1,2}),?\s(\d{4})', re.I)


def find_string_dates(data):  # Done
    data = data.replace('\x00', '')  # strip gaps from between string values

    # short_format_search
    sIdx = 0  # start search from beginning of data
    match = str_regex_short.search(data, sIdx)  # find match in data
    while match:
        sIdx = match.start() + 1  # subsequent search should consider 1 byte after this hit
        strA = match.group(1)
        strB = match.group(3)
        strC = match.group(4)

        try:
            valA = int(strA)
            valB = int(strB)
            valC = int(strC)

            # Regex allows for either strA or strC to be the year no guarantee on which is the month or day
            # Try parsing in each of the potential combinations
            try:  # consider data as Y-M-D
                ts = dt.datetime(valA, valB, valC)
                yield sIdx, ts
            except ValueError:
                pass
            try:  # consider data as Y-D-M
                ts = dt.datetime(valA, valC, valB)
                yield sIdx, ts
            except ValueError:
                pass
            try:  # consider data as M-D-Y
                ts = dt.datetime(valC, valA, valB)
                yield sIdx, ts
            except ValueError:
                pass
            try:  # consider data as D-M-Y
                ts = dt.datetime(valC, valB, valA)
                yield sIdx, ts
            except ValueError:
                pass
        except ValueError:
            pass
        match = str_regex_short.search(data, sIdx)  # find next match in data

    # long_format_search
    sIdx = 0  # start search from beginning of data
    match = str_regex_long.search(data, sIdx)  # find match in data
    while match:
        sIdx = match.start() + 1  # subsequent search should consider 1 byte after this hit
        strMonth = match.group(1)
        strDay = match.group(2).zfill(2)
        strYear = match.group(3)
        strDate = "{} {} {}".format(strYear, strMonth, strDay)

        try:  # try parsing the match using a full named month
            ts = dt.datetime.strptime(strDate, "%Y %B %d")
            yield sIdx, ts
        except ValueError:
            try:  # try parsing the match using an abbrev month
                ts = dt.datetime.strptime(strDate, "%Y %b %d")
                yield sIdx, ts
            except ValueError:
                pass
        match = str_regex_long.search(data, sIdx)  # find next match in data


ts_funcs = {
    "String": find_string_dates,
    "FILETIME": find_filetime,
    "SYSTEMTIME": find_systemtime,
    "DOSDateTime": find_dosdatetime,
    "UUID": find_uuid,
    "epoch": find_epoch
}


def find_timestamps(vData):
    for ts_type, ts_func in ts_funcs.iteritems():
        for pIdx, result in ts_func(vData):
            yield ts_type, pIdx, result


def get_sub_keys(key, path=''):
    # iterate all sub-keys of key returning (key,path)
    num_keys = key.get_number_of_sub_keys()

    for i in xrange(num_keys):
        cur_key = key.get_sub_key(i)
        new_path = os.path.join(path, cur_key.get_name())
        yield (cur_key, new_path)

        for result in get_sub_keys(cur_key, new_path):
            yield result


def get_soft_installdate(softHive):
    # get the windows install timestamp from software hive
    soft = pyregf.file()
    try:
        soft = pyregf.file()
        soft.open(softHive)
        vers_key = soft.get_key_by_path(r'Microsoft\Windows NT\CurrentVersion')
        inst_date = vers_key.get_value_by_name('InstallDate')
        stamp = dt.datetime.utcfromtimestamp(inst_date.get_data_as_integer())
    except (IOError, AttributeError):
        print('Error: InstallDate could not be determined.  Is this a SOFTWARE hive?\n\tFile: {}'.format(softHive))
        sys.exit(0)
    finally:
        soft.close()
    return stamp


def cmdArgParse():
    # parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='find_times: Find timestamps in the registry.')
    parser.add_argument('--debug',
                        help='Print debugging statements.',
                        action='store_true')
    parser.add_argument('-l',
                        dest='low_filter',
                        metavar='DATE',
                        help='The lower date filter, yyyy/mm/dd format.')
    parser.add_argument('-u',
                        dest='high_filter',
                        metavar='DATE',
                        help='The upper date filter, yyyy/mm/dd format.')
    parser.add_argument('--use-install',
                        dest='use_install',
                        metavar='HIVE',
                        help='Use the system install date in the specified Software hive as the lower date filter.')
    parser.add_argument('--use-mod',
                        dest='use_lastmodtime',
                        action='store_true',
                        help='filter out times later than the hive last modification time')
    parser.add_argument('--use-lastwrite',
                        dest='use_lastwrite',
                        action='store_true',
                        help='filter out times later than the owning key lastwrite time')
    parser.add_argument('-f',
                        dest='fname',
                        metavar='HIVE',
                        required=True,
                        help='The registry file to search.')

    args = parser.parse_args()

    # Set global debug value
    global DEBUG
    DEBUG = args.debug

    return args


def main():
    args = cmdArgParse()

    reg = pyregf.file()
    reg.open(args.fname)

    low_date = dt.datetime.min.date()
    high_date = dt.datetime.max.date()

    if args.use_install:  # parse install date from software hive
        low_date = get_soft_installdate(args.use_install).date()
    elif args.low_filter:  # use the date specified on cli
        low_date = dt.datetime.strptime(args.low_filter, '%Y/%m/%d').date()

    if args.use_lastmodtime:  # parse last mod from hive
        high_date = dt.datetime.utcfromtimestamp(os.path.getmtime(args.fname)).date()
    elif args.high_filter:  # use the date specified on cli
        high_date = dt.datetime.strptime(args.high_filter, '%Y/%m/%d').date()

    summaryText = '#Using date filters:\n#\t{}  -  {}\n'.format(low_date, high_date)
    if args.use_lastwrite:
        summaryText += '#\t[lastwrite] as additional upper filter\n'
    summaryText += '#{}'.format('\t'.join(['keyLastWrite', 'keyName', 'valueName', 'tsType', 'dataOffset', 'ts']))
    print(summaryText)

    for curKey, curPath in get_sub_keys(reg.get_root_key()):  # foreach key in regfile
        lastwrite = curKey.get_last_written_time()  # get the lastwrite time on key
        for i in xrange(curKey.number_of_values):  # foreach value in key
            curValue = curKey.get_value(i)
            vData = curValue.get_data()
            if vData == None:
                continue

            for ts_type, pIdx, result in find_timestamps(vData):  # foreach result we bruteforce
                if args.use_lastwrite and result > lastwrite:
                    continue  # failed lastwrite filter

                if low_date <= result.date() <= high_date:
                    print('\t'.join([str(lastwrite), str(curPath), str(curValue.get_name()), str(ts_type), str(pIdx), str(result)]))


if __name__ == '__main__':
    sys.exit(main())
