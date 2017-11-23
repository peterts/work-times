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
from datetime import datetime, time, timedelta
from collections import OrderedDict
import argparse


LOCK_EVENT = (4800, 4634)
UNLOCK_EVENT = (4826, 4801, 4624)

MAX_TIME = time(23, 59, 59)
MIN_TIME = time(0, 0, 0)
MAX_BREAK_TIME = timedelta(minutes=60)



def fix_locking_events(locking_events):
    for key in locking_events:
        le = locking_events[key]
        dt, event_type = le[-1]
        if event_type != UNLOCK_EVENT:
            le.append((datetime.combine(dt.date(), MIN_TIME), UNLOCK_EVENT))
        locking_events[key] = le[::-1]
    return locking_events


def get_locking_events(max_n_days, hand, flags, total):
    locking_events = OrderedDict()
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    while events:
        for event in events:
            event_id = int(event.EventID)
            if event_id in LOCK_EVENT or event_id in UNLOCK_EVENT:
                dt = datetime.strptime(str(event.TimeGenerated), '%Y-%m-%d %H:%M:%S')

                # Check if we have retrieved all logs that were asked for
                if max_n_days is not None and datetime.today().date() - dt.date() > max_n_days:
                    return fix_locking_events(locking_events)

                event_type = LOCK_EVENT if event_id in LOCK_EVENT else UNLOCK_EVENT
                day = str(dt.date())
                day_events = locking_events.get(day, [])
                if not day_events:
                    # If the last event of the day is not a lock, add this as the last event
                    if event_type != LOCK_EVENT:
                        now = datetime.now().replace(microsecond=0)
                        dt2 = now if dt.date() == now.date() else datetime.combine(dt.date(), MAX_TIME)
                        day_events.append((dt2, LOCK_EVENT))
                    day_events.append((dt, event_type))
                else:
                    if day_events[-1][1] == event_type:
                        continue
                    # If two consecutive lock-unlocks are too close in time, remove them
                    if event_type == UNLOCK_EVENT and len(day_events) >= 3:
                        if day_events[-2][0] - day_events[-1][0] < MAX_BREAK_TIME:
                            day_events = day_events[:-2]
                    day_events.append((dt, event_type))
                locking_events[day] = day_events
        events = win32evtlog.ReadEventLog(hand, flags, 0)

    return fix_locking_events(locking_events)


if __name__ == "__main__":
    # Read max_n_days
    parser = argparse.ArgumentParser()
    parser.add_argument("max_n_days", help="the type of version bump",
                        type=int, default=None)
    args = parser.parse_args()
    max_n_days = None if args.max_n_days is None else  timedelta(days=args.max_n_days)

    # Define some variables
    hand = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)

    locking_events = get_locking_events(max_n_days, hand, flags, total)

    ts = lambda e: str(e[0].time())
    for date_str, ev in locking_events.items():
        times_str = ", ".join(ts(u) + "-" + ts(l) for u, l in zip(ev[::2], ev[1::2]))
        print("{}: {}".format(date_str, times_str))

