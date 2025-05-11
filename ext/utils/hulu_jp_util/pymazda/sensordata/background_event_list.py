import datetime
import random

from ext.utils.hulu_jp_util.pymazda.sensordata.sensor_data_util import timestamp_to_millis

class BackgroundEvent:
    def __init__(self, type, timestamp):
        self.type = type
        self.timestamp = timestamp

    def to_string(self):
        return f"{self.type},{self.timestamp}"

class BackgroundEventList:
    def __init__(self):
        self.background_events = []

    def randomize(self, sensor_collection_start_timestamp):
        self.background_events = []

        if random.randrange(0, 10) > 0:
            return

        now_timestamp = datetime.datetime.now(datetime.timezone.utc)
        time_since_sensor_collection_start = int((now_timestamp - sensor_collection_start_timestamp) / datetime.timedelta(milliseconds=1))

        if time_since_sensor_collection_start < 10000:
            return

        paused_timestamp = timestamp_to_millis(sensor_collection_start_timestamp) + random.randrange(800, 4500)
        resumed_timestamp = paused_timestamp + random.randrange(2000, 5000)

        self.background_events.append(BackgroundEvent(2, paused_timestamp))
        self.background_events.append(BackgroundEvent(3, resumed_timestamp))

    def to_string(self):
        return "".join(map(lambda event: event.to_string(), self.background_events))
