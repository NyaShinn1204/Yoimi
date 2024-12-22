import uuid
import time
import json
import base64
import logging
from typing import Dict

class TraceHeader:
    def get_header_name(self) -> str:
        raise NotImplementedError("Subclasses should implement this method.")

    def get_header_value(self) -> str:
        raise NotImplementedError("Subclasses should implement this method.")

class DistributedTracing:
    @staticmethod
    def generate_normalized_timestamp() -> int:
        return int(time.time() * 1000)
    @staticmethod
    def generate_random_bytes(length: int) -> str:
        """指定された長さのランダムな16進数文字列を生成"""
        random_bytes = uuid.uuid4().hex  # ランダムなUUIDを16進数文字列で生成
        return random_bytes[:length]  # 指定された長さだけ切り取る

    @staticmethod
    def generate_trace_id() -> str:
        """32文字のランダムなトレースIDを生成"""
        return DistributedTracing.generate_random_bytes(32)

    @staticmethod
    def generate_span_id() -> str:
        """16文字のランダムなスパンIDを生成"""
        return DistributedTracing.generate_random_bytes(16)


class TraceConfiguration:
    def __init__(self, sampled: bool, account_id, application_id, trusted_account_id):
        self.sampled = sampled
        self.account_id = account_id
        self.application_id = application_id
        self.trusted_account_id = trusted_account_id

    def is_sampled(self) -> bool:
        """サンプリングされているかどうかを返すメソッド"""
        return self.sampled


class TraceContext:
    def __init__(self, trace_configuration: TraceConfiguration, trace_id: str,
                 account_id: str, application_id: str, parent_id: str, vendor: str):
        self.trace_configuration = trace_configuration
        self.trace_id = trace_id
        self.account_id = account_id
        self.application_id = application_id
        self.parent_id = parent_id
        self.vendor = vendor
        self.trace_payload = None

    def get_sampled(self) -> str:
        """サンプリング情報を16進数で返す"""
        sampled_value = 1 if self.trace_configuration.is_sampled() else 0
        return f"{sampled_value:02x}"

    def get_account_id(self) -> str:
        return self.account_id

    def get_application_id(self) -> str:
        return self.application_id

    def get_parent_id(self) -> str:
        return self.parent_id

    def get_vendor(self) -> str:
        return self.vendor

    def get_trace_id(self) -> str:
        return self.trace_id


class TraceParent:
    TRACE_PARENT_HEADER = "traceparent"
    TRACE_PARENT_HEADER_FMT = "%s-%s-%s-%s"
    TRACE_PARENT_VERSION = 0

    def __init__(self, trace_context: TraceContext):
        self.parent_id = DistributedTracing.generate_span_id()
        self.trace_context = trace_context

    @staticmethod
    def create_trace_parent(trace_context: TraceContext) -> "TraceParent":
        return W3CTraceParent(trace_context)

    def get_header_name(self) -> str:
        return self.TRACE_PARENT_HEADER

    def get_parent_id(self) -> str:
        return self.parent_id

    def get_version(self) -> str:
        return format(self.TRACE_PARENT_VERSION, "02x")
class TraceState(TraceHeader):
    TRACE_STATE_HEADER = "tracestate"
    TRACE_STATE_PARENT_TYPE = 2
    TRACE_STATE_VERSION = 0

    def __init__(self, trace_context: TraceContext):
        self.trace_context = trace_context
        self.timestamp_ms = DistributedTracing.generate_normalized_timestamp()
        self.entries: Dict[str, str] = {}

    @staticmethod
    def create_trace_state(trace_context: TraceContext) -> "TraceState":
        return W3CTraceState(trace_context)

    def get_header_name(self) -> str:
        return self.TRACE_STATE_HEADER
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
class W3CTraceParent(TraceParent):
    TRACE_PARENT_HEADER_REGEX = r"^(\\d+)-([A-Fa-f0-9]{32})-([A-Fa-f0-9]{16})?-(\\d+)$"

    def __init__(self, trace_context: TraceContext):
        super().__init__(trace_context)

    def get_header_value(self) -> str:
        version = self.get_version()
        trace_id = self.trace_context.trace_id
        parent_id = self.get_parent_id()
        sampled = self.trace_context.get_sampled()

        header_value = f"{version}-{trace_id}-{parent_id}-{sampled}"
        return header_value
class W3CTraceState(TraceState):
    TRACE_STATE_HEADER_FMT = "{version}-{type}-{account_id}-{app_id}-{parent_id}--{timestamp}"
    
    def __init__(self, trace_context: TraceContext):
        super().__init__(trace_context)
        self.entries[trace_context.get_vendor()] = self.get_vendor_state()

    def get_header_value(self) -> str:
        return ",".join(f"{key}={value}" for key, value in self.entries.items())

    def get_vendor_state(self) -> str:
        return self.TRACE_STATE_HEADER_FMT.format(
            version=self.TRACE_STATE_VERSION,
            type=self.TRACE_STATE_PARENT_TYPE,
            account_id=self.trace_context.get_account_id(),
            app_id=self.trace_context.get_application_id(),
            parent_id=self.trace_context.get_parent_id(),
            timestamp=self.timestamp_ms,
        )

def Trace_return():
    # Gemerate trace_parent
    trace_config = TraceConfiguration(sampled=False, account_id=None, application_id=None, trusted_account_id=None)
    trace_id = DistributedTracing.generate_trace_id()
    trace_context = TraceContext(
        trace_configuration=trace_config,
        trace_id=trace_id,
        account_id=None,
        application_id=None,
        parent_id=None,
        vendor=None
    )

    trace_parent = TraceParent.create_trace_parent(trace_context)
    print(trace_parent.get_header_name())
    print(trace_parent.get_header_value())
    
    # Generate trace_state
    context = TraceContext(
        trace_configuration=None,
        trace_id=None,
        account_id="2646341",
        application_id="627412969",
        parent_id=trace_parent.get_parent_id()+"--",
        vendor="2646341@nr"
    )

    trace_state = TraceState.create_trace_state(context)
    print(trace_state.get_header_name())
    print(trace_state.get_header_value())
    
    # Gemerate newrelic(trace_payload)
    trace_config = TraceConfiguration(sampled=False, account_id="2646341", application_id="627412969", trusted_account_id="2646341")
    trace_context = TraceContext(
        trace_configuration=trace_config,
        trace_id=trace_id,
        account_id=None,
        application_id=None,
        parent_id=trace_parent.get_parent_id(),
        vendor=None
    )
    
    trace_payload = TracePayload(trace_context)
    print(trace_payload.get_header_name())
    print(trace_payload.get_header_value())
    
    return trace_payload.get_header_value(), trace_parent.get_header_value(), trace_state.get_header_value()

print(Trace_return())