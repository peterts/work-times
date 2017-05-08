"""
To activate logging of computer locking:
    run -> gpedit.msc
Then configure the following:
    Computer Configuration ->
    Windows Settings ->
    Security Settings ->
    Advanced Audit Policy Configuration ->
    System Audit Policies - Local Group Policy Object ->
    Logon/Logoff ->
    Audit Other Login/Logoff Events
"""


import win32evtlog
import sys
from datetime import datetime, timedelta
from collections import OrderedDict


# Define some variables
hand = win32evtlog.OpenEventLog(None, "Security")
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)

LOCK_EVENT = 4800
UNLOCK_EVENT = 4801

# The maximum number of days to display results for
max_n_days = None
if len(sys.argv) > 1:
    try:
        max_n_days = int(sys.argv[1])
        if max_n_days < 1:
            max_n_days = None
        max_n_days = timedelta(days=max_n_days)
    except TypeError:
        pass

# Get the work times
# For each date, this will be the earliest unlock time until the latest lock time
work_times = OrderedDict()
end = False
while not end:
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    if events:
        for event in events:
            event_id = int(event.EventID)
            if event_id in [LOCK_EVENT, UNLOCK_EVENT]:
                dt = datetime.strptime(str(event.TimeGenerated), '%Y-%m-%d %H:%M:%S')
                if max_n_days is not None and datetime.today().date() - dt.date() > max_n_days:
                    end = True
                    break
                date_str = str(dt.date())
                if date_str not in work_times:
                    if event_id == LOCK_EVENT:
                        work_times[date_str] = [None, dt.time()]
                    else:
                        work_times[date_str] = [dt.time(), None]
                else:
                    if event_id == LOCK_EVENT:
                        if work_times[date_str][1] is None or dt.time() > work_times[date_str][1]:
                            work_times[date_str][1] = dt.time()
                    else:
                        if work_times[date_str][0] is None or dt.time() < work_times[date_str][0]:
                            work_times[date_str][0] = dt.time()
    else:
        end = True

# Display result
for date_str in work_times:
    print("{}: {}-{}".format(date_str, *work_times[date_str]))
