# Importing Libraries
from flask import Flask, request, jsonify
from pymongo import MongoClient
import pandas as pd

# Creating a new Flask web application instance
app = Flask(__name__)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
database = client['Client']
collection = database['logs']

# Function to get the next event ID
def get_next_event_id():
    last_event = collection.find_one(sort=[("Event ID Occurrences", -1)])
    if last_event:
        return last_event['Event ID Occurrences'] + 1
    else:
        return 1

# Function to get the total events count
def get_total_events_count():
    return collection.count_documents({})

# Function to check if an event already exists with the same fields
def is_duplicate(event):
    query = {
        "Event ID": event.get("Event ID"),
        "Time Created": event.get("Time Created"),
        "Score": event.get("Score"),
        "Severity": event.get("Severity"),
        "Message": event.get("Message"),
        "IP Address": event.get("IP Address"),
        "Machine Name": event.get("Machine Name"),
        "Log Name": event.get("Log Name")
    }
    return collection.count_documents(query) > 0


# Defining a route '/receive_logs' that accepts POST requests
@app.route('/receive_logs', methods=['POST'])
def receive_logs():
    data = request.get_json()
    if data:
        total_events_count = get_total_events_count()
        if isinstance(data, list):
            for event in data:
                if not is_duplicate(event):
                    total_events_count += 1
                    event['Event ID Occurrences'] = get_next_event_id()
                    event['Total Events Count'] = total_events_count
                    collection.insert_one(event)
        else:
            if not is_duplicate(data):
                total_events_count += 1
                data['Event ID Occurrences'] = get_next_event_id()
                data['Total Events Count'] = total_events_count
                collection.insert_one(data)

        return jsonify({'message': 'Logs received and processed'}), 200
    else:
        return jsonify({'message': 'No data received'}), 400

# Running the Flask application with debugging enabled, accessible from any host
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)

