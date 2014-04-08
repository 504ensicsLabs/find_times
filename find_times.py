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


import os
import sys
import time
import struct
import codecs
import calendar
import uuid
import re
import pyregf
from calendar import isleap
from time import mktime
from datetime import datetime

sys.stdout = codecs.getwriter('utf-8')(sys.stdout)


'''
###### TODO & COMMENTS #####

Is UUID just a less accurate (60 bit vs 64) version of FILETIME?

#############################
'''


def get_values(key):
    num_values = key.get_number_of_values()

    for i in range(num_values):
        yield key.get_value(i)


def process_sub_keys(key, path=""):
    # recurses all subkeys of key
    num_keys = key.get_number_of_sub_keys()

    for i in range(num_keys):
        cur_key = key.get_sub_key(i)

        new_path = os.path.join(path, cur_key.get_name())

        yield (cur_key, new_path)

        for (skey, spath) in process_sub_keys(cur_key, new_path):
            sub_path = os.path.join(spath)
            yield (skey, sub_path)


# Human time (GMT): Fri, 01 Mar 2013 00:00:00 GMT
# low_date = time.gmtime(1362096000)
low_date = time.gmtime(0)


# Human time (GMT): Sun, 01 Sep 2013 00:00:00 GMT
# high_date = time.gmtime(1377993600)
# 2^31-1
high_date = time.gmtime(2147483647)


def find_filetime(vtype, data):
    max_size = len(data)

    for i in xrange(max_size):
        fmts = [">Q", "<Q"]
        for fmt in fmts:
            try:
                intval = struct.unpack(fmt, data[i:i + 8])[0]
            except struct.error:
                continue

            toepoch = (intval - 116444736000000000) // 10000000

            try:
                temp = time.gmtime(float(toepoch))
            except ValueError:
                continue

            if low_date < temp < high_date:
                yield (temp, intval, i)


def find_dosdatetime(vtype, data):
    max_size = len(data)

    for i in xrange(max_size):
        try:
            (tdate, ttime) = struct.unpack("<HH", data[i:i + 4])
        except struct.error:
            continue

        secs = (ttime & 0x1F) * 2
        mins = (ttime & 0x7E0) >> 5
        hours = (ttime & 0xF800) >> 11

        day = tdate & 0x1F
        month = (tdate & 0x1E0) >> 5
        year = ((tdate & 0xFE00) >> 9) + 1980

        try:
            ts = datetime(year, month, day, hours, mins, secs)
        except ValueError:
            try:
                ts = datetime(year, month, day)
            except ValueError:
                # print "year: %d | %d | %d | %d | %d | %d" % (year, month, day, hours, mins, secs)
                continue

        intval = int(ts.strftime('%s'))
        temp = time.gmtime(float(intval))

        if low_date < temp < high_date:
            yield (temp, intval, i)


def find_epoch(vtype, data):
    max_size = len(data)

    fmts = [">i", "<i"]
    for i in range(max_size):
        for fmt in fmts:
            try:
                intval = struct.unpack(fmt, data[i:i + 4])[0]
            except struct.error:
                continue

            temp = time.gmtime(float(intval))

            if low_date < temp < high_date:
                yield (temp, intval, i)


# Number of 100ns ticks per clock tick (second).
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
        ret = datetime(year, month, days, hours, mins, secs, milli_secs * 1000)
    except:
        ret = None

    return ret


def find_systemtime(vtype, data):
    max_size = len(data)

    for i in xrange(max_size):
        try:
            timestamp = struct.unpack("<Q", data[i:i + 8])[0]
        except struct.error:
            continue

        ts = parse_systemtime(timestamp)

        if not ts:
            continue

        try:
            intval = int(ts.strftime('%s'))
        except ValueError:
            continue

        temp = time.gmtime(float(intval))

        if low_date < temp < high_date:
            yield (temp, intval, i)


def find_uuid(vtype, data):
    max_size = len(data)

    for i in xrange(max_size):
        timestamp = data[i:i + 16]

        try:
            ts_uuid = uuid.UUID(bytes=timestamp)
        except ValueError:
            continue

        uuid1time = ts_uuid.time

        try:
            ts = datetime.fromtimestamp((uuid1time - 0x01b21dd213814000L) * 100 / 1e9)
        except ValueError:
            continue
        try:
            intval = int(ts.strftime('%s'))
        except ValueError:
            intval = int(0)
        temp = time.gmtime(float(intval))

        if low_date < temp < high_date:
            yield (temp, intval, i)


class _find_string:
    # for finding "string"-like dates
    def __init__(self, regex, length, day_idx, month_idx, year_idx):
        self.regex = regex
        self.length = length
        self.day_idx = day_idx
        self.month_idx = month_idx
        self.year_idx = year_idx


regexes = [
    _find_string("(\d{1,2})-(\d{2})-(\d{4})", 10, 1, 2, 3),  # (d)d-mm-yyyy
    _find_string("(\d{1,2})-(\d{2})-(\d{4})", 10, 2, 1, 3),  # (m)m-dd-yyyy
    _find_string("(\d{1,2})-(\d{2})-(\d{2})", 8, 1, 2, 3),  # (d)d-mm-yy
    _find_string("(\d{1,2})-(\d{2})-(\d{2})", 8, 2, 1, 3),  # (m)m-dd-yy
    _find_string("(\d{1,2})-(\d{2})-(\d{2})", 8, 2, 3, 1),  # yy-dd-mm
    _find_string("(\d{1,2})-(\d{2})-(\d{2})", 8, 3, 2, 1),  # yy-mm-dd
    _find_string("(\d{4})-(\d{2})-(\d{2})", 10, 3, 2, 1),  # yyyy-mm-dd

    # all the previous ones but with / instead of -
    _find_string("(\d{1,2})/(\d{2})/(\d{4})", 10, 1, 2, 3),  # (d)d/mm/yyyy
    _find_string("(\d{1,2})/(\d{2})/(\d{4})", 10, 2, 1, 3),  # (m)m/dd/yyyy
    _find_string("(\d{1,2})/(\d{2})/(\d{2})", 8, 1, 2, 3),  # (d)d/mm/yy
    _find_string("(\d{1,2})/(\d{2})/(\d{2})", 8, 2, 1, 3),  # (m)m/dd/yy
    _find_string("(\d{1,2})/(\d{2})/(\d{2})", 8, 2, 3, 1),  # yy/dd/mm
    _find_string("(\d{1,2})/(\d{2})/(\d{2})", 8, 3, 2, 1),  # yy/mm/dd
    _find_string("(\d{4})/(\d{2})/(\d{2})", 10, 3, 2, 1),  # yyyy/mm/dd

    # This regex can find dates listed as "Month Day, Year" or "Month Day Year" and has both full & common abrev for each month
    # it is listed twice due to having such different length requirements
    _find_string("(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Aug|Sept|Oct|Nov|Dec)\s(\d{1,2})[,]{0,1} (\d{4})", 19, 2, 1, 3),
    _find_string("(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Aug|Sept|Oct|Nov|Dec)\s(\d{1,2})[,]{0,1} (\d{4})", 10, 2, 1, 3),
]


# this must have all entries contained in the above regex
months = {
    "January"   : 1,
    "Jan"       : 1,
    "February"  : 2,
    "Feb"       : 2,
    "March"     : 3,
    "April"     : 4,
    "May"       : 5,
    "June"      : 6,
    "July"      : 7,
    "August"    : 8,
    "Aug"       : 8,
    "September" : 9,
    "Sept"      : 9,
    "Oct"       : 10,
    "October"   : 10,
    "November"  : 11,
    "Nov"       : 11,
    "December"  : 12,
    "Dec"       : 12,
}


def find_string_dates(vtype, data):
    # this is n^n^n^n^n^n^n^n^n .. or something similar
    data = data.replace("\x00", "")

    max_size = len(data)

    for i in xrange(max_size):
        for r in regexes:
            # read in the regex-defined length
            timestamp = data[i:i + r.length + 1]

            # try to match the regex, if match extract values
            match = re.match(r.regex, timestamp)
            if match:
                day = match.group(r.day_idx)
                month = match.group(r.month_idx)
                year = match.group(r.year_idx)

                try:
                    day = int(day)
                except:
                    continue

                try:
                    year = int(year)
                except:
                    continue

                if month in months:
                    month = months[month]
                else:
                    month = int(month)

                try:
                    ts = datetime(year, month, day)
                except ValueError:
                    continue

                try:
                    intval = int(ts.strftime('%s'))
                except ValueError:
                    continue

                temp = time.gmtime(float(intval))

                if low_date < temp < high_date:
                    yield (temp, intval, i)


# these functions must return None to indicate not valid
# don't add back
#  "epoch"
ts_funcs = {
    "String"       : find_string_dates,
    "FILETIME"     : find_filetime,
    "SYSTEMTIME"   : find_systemtime,
    "DOSDateTime"  : find_dosdatetime,
    "UUID"         : find_uuid,
    "epoch"        : find_epoch
}


def find_timestamps(vtype, vdata):
    for func in ts_funcs:
        timestamps = ts_funcs[func](vtype, vdata)
        if timestamps:
            for (temp, intval, i) in timestamps:
                yield (func, temp, intval, i)


def get_regfile_lastmodtime(fname):
    data = open(fname, "rb").read(20)
    data = data[12:]
    try:
        intval = struct.unpack('<Q', data[:8])[0]
    except struct.error:
        print "Couldn't parse last modification time. Exiting."
        sys.exit(0)

    toepoch = (intval - 116444736000000000) // 10000000
    try:
        temp = time.gmtime(float(toepoch))
    except ValueError:
        print "Couldn't parse last modification time. Exiting."
        sys.exit(0)

    return temp


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Find timestamps in the registry.')
    parser.add_argument('--use-install-time', dest='use_install', help='Use the system install time in the specified Software hive as the lower time filter.')
    parser.add_argument('--use-last-modification-time', dest='use_lastmodtime', action='store_true', help='Use the last access time of the file as the upper time filter.')
    parser.add_argument('-l', help='The lower time filter, yyyy/mm/dd format.')
    parser.add_argument('-u', help='The upper time filter, yyyy/mm/dd format.')
    parser.add_argument('-f', required=True, help='The registry file to search.')
    parser.add_argument('-p', dest='filter_after_lastwrite', action='store_true', help='filter out times later than the owning key\'s lastwrite time')
    args = parser.parse_args()

    fname = args.f
    reg = pyregf.file()
    reg.open(fname)
    rk = reg.get_root_key()

    global low_date
    global high_date

    # set low_date
    if args.use_install:  # use the system installation date stored in the provided software hive
        soft = pyregf.file()
        soft.open(args.use_install)
        soft_key = soft.get_root_key()
        key = soft_key.get_sub_key_by_path('Microsoft\Windows NT\CurrentVersion')
        if key:
            inst_date = key.get_value_by_name('InstallDate')
            low_date = time.gmtime(inst_date.get_data_as_integer())
        else:
            print 'InstallDate could not be determined. Is this a Software registry file? Exiting.'
            sys.exit(0)
    elif args.l:  # use the date specified on the cmdline
        low_date = time.strptime(args.l, "%Y/%m/%d")

    # set high_date
    if args.use_lastmodtime:
        # get the internal last access time
        high_date = get_regfile_lastmodtime(fname)
    elif args.u:
        # convert string to int
        high_date = time.strptime(args.u, "%Y/%m/%d")

    # This may have incorrect granularity in that we only print down to days.
    print("Using date filters lower: %s upper: %s" % (time.strftime("%Y/%m/%d", low_date), time.strftime("%Y/%m/%d", high_date)))

    # for each key
    for (key, path) in process_sub_keys(rk):
        # print key.get_last_written_time()

        lastwrite = str(key.get_last_written_time()).split(".")[0]
        for value in get_values(key):
            # idx = 0
            vdata = value.get_data()

            if vdata == None:
                continue

            vtype = value.get_type()

            for (ts_type, timestamp, intval, val_idx) in find_timestamps(vtype, vdata):
                try:
                    readablets = datetime.fromtimestamp(mktime(timestamp))
                    outstr = "%s\t%s\t%s\t%s\t%s\t%s\t%s" % (lastwrite, str(readablets), ts_type, path, value.get_name(), intval, val_idx)
                except Exception:
                    pass
                if args.filter_after_lastwrite:
                    blarg = time.gmtime(calendar.timegm(key.get_last_written_time().utctimetuple()))
                    # print "%s %s" % (timestamp, blarg)
                    if timestamp <= blarg:
                        print outstr
                else:
                    print outstr


if __name__ == "__main__":
    main()








