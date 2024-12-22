# 必要なクラスをインポートして準備
import base64
import json
import logging
import time

# TraceContextクラスやDistributedTracingモジュールは仮定で記述します。実際の内容に合わせてください。
class TraceContext:
    def __init__(self, trace_configuration, trace_id, parent_id=None):
        self.trace_configuration = trace_configuration
        self.trace_id = trace_id
        self.parent_id = parent_id
        self.trace_payload = None

    def get_parent_id(self):
        return self.parent_id

    def get_trace_id(self):
        return self.trace_id

class TraceConfiguration:
    def __init__(self, account_id, application_id, trusted_account_id):
        self.account_id = account_id
        self.application_id = application_id
        self.trusted_account_id = trusted_account_id

class TracePayload:
    ACCOUNT_ID_KEY = "ac"
    APP_ID_KEY = "ap"
    CALLER_TYPE = "Mobile"
    DATA_KEY = "d"
    GUID_KEY = "id"
    MAJOR_VERSION = 0
    MINOR_VERSION = 2
    PAYLOAD_TYPE_KEY = "ty"
    TIMESTAMP_KEY = "ti"
    TRACE_ID_KEY = "tr"
    TRACE_PAYLOAD_HEADER = "newrelic"
    TRUST_ACCOUNT_KEY = "tk"
    VERSION_KEY = "v"

    def __init__(self, trace_context):
        self.trace_context = trace_context
        trace_payload = trace_context.trace_payload
        self.span_id = trace_payload.span_id if trace_payload else trace_context.get_parent_id()
        self.timestamp_ms = self.generate_normalized_timestamp()

    def generate_normalized_timestamp(self):
        return int(time.time() * 1000)

    def as_base64_json(self):
        try:
            return base64.b64encode(self.as_json().encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"asBase64Json: {str(e)}")
            return ""

    def as_json(self):
        json_obj = {}
        json_array = [0, 2]
        json_obj2 = {}
        try:
            json_obj2[self.PAYLOAD_TYPE_KEY] = "Mobile"
            json_obj2[self.ACCOUNT_ID_KEY] = self.trace_context.trace_configuration.account_id
            json_obj2[self.APP_ID_KEY] = self.trace_context.trace_configuration.application_id
            json_obj2[self.TRACE_ID_KEY] = self.trace_context.trace_id
            json_obj2[self.GUID_KEY] = self.span_id
            json_obj2[self.TIMESTAMP_KEY] = self.timestamp_ms
            json_obj2[self.TRUST_ACCOUNT_KEY] = self.trace_context.trace_configuration.trusted_account_id
            json_obj[self.VERSION_KEY] = json_array
            json_obj[self.DATA_KEY] = json_obj2
        except Exception as e:
            logging.error(f"Unable to create payload asJSON: {str(e)}")
        return json.dumps(json_obj, separators=(',', ':'))

    def get_header_name(self):
        return self.TRACE_PAYLOAD_HEADER

    def get_header_value(self):
        return self.as_base64_json()

    def get_span_id(self):
        return self.span_id

    def get_trace_id(self):
        return self.trace_context.get_trace_id()

# テスト用の設定
trace_config = TraceConfiguration(account_id="2646341", application_id="627412969", trusted_account_id="2646341")
trace_context = TraceContext(trace_configuration=trace_config, trace_id="uuid_id", parent_id="16_len_id")

# TracePayloadインスタンスを作成
trace_payload = TracePayload(trace_context)

# 結果を表示
print("Header Name:", trace_payload.get_header_name())
print("Header Value (Base64):", trace_payload.get_header_value())
print("Span ID:", trace_payload.get_span_id())
print("Trace ID:", trace_payload.get_trace_id())
