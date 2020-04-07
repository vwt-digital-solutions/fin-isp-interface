import datetime
import pytz


class FormatError(Exception):
    def __init__(self, exception_id, function_name=None, fields=None,
                 description=None):
        timezone = pytz.timezone("Europe/Amsterdam")
        timestamp = datetime.datetime.now(tz=timezone)

        exception_list = {
            4030: "Duplicate message from topic"
        }

        self.properties = {
            "error": {
                "exception_id": exception_id,
                "function_name": function_name,
                "message": exception_list.get(exception_id, None),
                "fields": fields,
                "description": description,
                "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            }
        }
