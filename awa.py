import time
import uuid
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
        """Generates a random string of the specified length."""
        result = ""
        while len(result) < length:
            result += uuid.uuid4().hex  # UUIDを生成し、ハイフンを除いた文字列に変換
        return result[:length]

    @staticmethod
    def generate_span_id() -> str:
        """Generates a 16-character span ID."""
        return DistributedTracing.generate_random_bytes(16)



class TraceContext:
    def __init__(self, account_id: str, application_id: str, parent_id: str, vendor: str):
        self.account_id = account_id
        self.application_id = application_id
        self.parent_id = parent_id
        self.vendor = vendor

    def get_account_id(self) -> str:
        return self.account_id

    def get_application_id(self) -> str:
        return self.application_id

    def get_parent_id(self) -> str:
        return self.parent_id

    def get_vendor(self) -> str:
        return self.vendor


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


# サンプルの使用例
if __name__ == "__main__":
    # サンプルの TraceContext を作成
    context = TraceContext(
        account_id="2646341",
        application_id="627412969",
        parent_id=DistributedTracing.generate_span_id(),
        vendor="2646341@nr"
    )

    # TraceState を生成
    trace_state = TraceState.create_trace_state(context)

    # ヘッダー名と値を表示
    print(trace_state.get_header_name())  # "tracestate"
    print(trace_state.get_header_value())  # ベンダー情報を含むトレースステート値
