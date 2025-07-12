import requests
import socket
import win32evtlog
import time
from pymongo import MongoClient
from datetime import datetime
import pywintypes
from bson import ObjectId

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
database = client['Client']
collection = database['logs']

# Initialize counters for total events and occurrences of specific event IDs.
total_events_count = 0
event_id_occurrences = {}

# Function to recursively convert event data into a format suitable for JSON serialization.
def convert_event_data(data):
    if isinstance(data, dict):
        for key, value in data.items():
            data[key] = convert_event_data(value)
    elif isinstance(data, list):
        data = [convert_event_data(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, pywintypes.TimeType):
        return datetime(data.year, data.month, data.day, data.hour, data.minute, data.second).isoformat()
    elif isinstance(data, datetime):
        return data.isoformat()
    return data

# Define the severity levels based on a numeric score.
def severity(score):
    if score >= 90:
        return "Danger"
    elif score >= 60:
        return "Caution"
    else:
        return "Normal"

# Function to retrieve the IP address of the current machine.
def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except Exception as e:
        print(f"Error obtaining IP address: {e}")
        return "127.0.0.1"
    return ip_address

# Function to save event data into the MongoDB database.
def save_to_mongodb(event_data):
    try:
        collection.insert_one(event_data)
        print("Log saved to MongoDB successfully.")
    except Exception as e:
        print(f"Failed to save log to MongoDB: {e}")

# Predefined event IDs, descriptions, and severity scores to search for and display.
chosen_event_id = {
    1102: ("Audit log was cleared. This can relate to a potential attack", 95),
    4624: ("Successful account log on", 25),
    4625: ("Failed account log on", 40),
    4634: ("An account logged off", 10),
    4648: ("A logon attempt was made with explicit credentials", 70),
    4657: ("A registry value was changed", 60),
    4672: ("Admin privileges are being used", 80),
    4697: ("An attempt was made to install a service", 75),
    4698: ("Events related to Windows scheduled tasks being created", 65),
    4699: ("Events related to Windows scheduled tasks being modified", 65),
    4700: ("Events related to Windows scheduled tasks being deleted", 85),
    4701: ("Events related to Windows scheduled tasks being enabled", 60),
    4702: ("Events related to Windows scheduled tasks being disabled", 60),
    4719: ("System audit policy was changed", 90),
    4720: ("A user account was created", 70),
    4722: ("A user account was enabled", 50),
    4723: ("An attempt was made to change the password of an account", 60),
    4725: ("A user account was disabled", 50),
    4728: ("A user was added to a privileged global group", 90),
    4732: ("A user was added to a privileged local group", 85),
    4735: ("A privileged local group was modified", 80),
    4737: ("A privileged global group was modified", 80),
    4738: ("A user account was changed", 75),
    4740: ("A user account was locked out", 55),
    4755: ("A privileged universal group was modified", 80),
    4756: ("A user was added to a privileged universal group", 85),
    4767: ("A user account was unlocked", 45),
    4772: ("A Kerberos authentication ticket request failed", 30),
    4777: ("The domain controller failed to validate the credentials of an account", 75),
    4782: ("Password hash an account was accessed", 95),
    4946: ("A rule was added to the Windows Firewall exception list", 55),
    4947: ("A rule was modified in the Windows Firewall exception list", 55),
    4950: ("A setting was changed in Windows Firewall", 80),
    4954: ("Group Policy settings for Windows Firewall has changed", 70),
    5025: ("The Windows Firewall service has been stopped", 75),
    5031: ("Windows Firewall blocked an application from accepting incoming traffic", 65),
    5152: ("A network packet was blocked by Windows Filtering Platform", 60),
    5153: ("A network packet was blocked by Windows Filtering Platform", 60),
    5155: ("Windows Filtering Platform blocked an application or service from listening on a port", 70),
    5157: ("Windows Filtering Platform blocked a connection", 70),
    5447: ("A Windows Filtering Platform filter was changed", 60),
    6416: ("A new external device was recognized by the system", 40),
}

# Function to read and process Windows Event Logs.
def read_event_logs(logtype, last_processed_timestamp):
    global total_events_count, event_id_occurrences
    hand = win32evtlog.OpenEventLog(None, logtype)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events_to_send = []

    try:
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                event_id = event.EventID & 0x1FFFFFFF
                if event_id in chosen_event_id:
                    event_timestamp = pywintypes.Time(event.TimeGenerated).Format('%Y-%m-%d %H:%M:%S')
                    event_datetime = datetime.strptime(event_timestamp, '%Y-%m-%d %H:%M:%S')
                    if event_datetime > last_processed_timestamp:
                        description, score = chosen_event_id[event_id]
                        total_events_count += 1
                        event_id_occurrences[event_id] = event_id_occurrences.get(event_id, 0) + 1

                        event_data = {
                            "Event ID": event_id,
                            "Time Created": event_timestamp,
                            "Score": score,
                            "Severity": severity(score),
                            "Message": description,
                            "IP Address": get_ip_address(),
                            "Machine Name": event.ComputerName,
                            "Log Name": logtype,
                            "Event ID Occurrences": event_id_occurrences[event_id],
                            "Total Events Count": total_events_count,
                        }
                        events_to_send.append(event_data)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        win32evtlog.CloseEventLog(hand)

    return events_to_send, last_processed_timestamp

# Main function orchestrating the log monitoring and data forwarding process.
def main():
    server_endpoint = "http://192.168.100.141:3000/receive_logs"
    log_types = ["Application", "Security", "System"]
    last_processed_timestamp = datetime.now()

    while True:
        for logtype in log_types:
            events_to_send, last_processed_timestamp = read_event_logs(logtype, last_processed_timestamp)
            for event_data in events_to_send:
                event_data = convert_event_data(event_data)

                response = requests.post(server_endpoint, json=event_data)
                if response.status_code == 200:
                    print("Log data sent successfully:", event_data)
                else:
                    print(f"Failed to send log data. Status code: {response.status_code}, Response: {response.text}")

        time.sleep(5)

# Running the script
if __name__ == "__main__":
    main()
