"""Abstract streaming interfaces, Kafka client implementations, and in-memory mock bus."""

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable, Tuple

logger = logging.getLogger("sentinel.streaming.bus")


@dataclass
class StreamMessage:
    """Canonical representation of a consumed streaming message."""
    topic: str
    partition: int
    offset: int
    key: Optional[str]
    value: bytes
    headers: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[float] = None


class StreamProducer(ABC):
    """Abstract interface for event stream producers."""

    @abstractmethod
    def produce(
        self,
        topic: str,
        value: bytes,
        key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Publish a message to a topic."""
        pass

    @abstractmethod
    def flush(self, timeout: Optional[float] = None) -> int:
        """Wait for all outstanding in-flight messages to be delivered. Returns remaining count."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Release producer resources."""
        pass


class StreamConsumer(ABC):
    """Abstract interface for event stream consumers."""

    @abstractmethod
    def subscribe(self, topics: List[str]) -> None:
        """Subscribe to a list of topics."""
        pass

    @abstractmethod
    def poll(self, timeout: float = 1.0) -> Optional[StreamMessage]:
        """Poll for a single message from subscribed topics."""
        pass

    @abstractmethod
    def commit(self, message: Optional[StreamMessage] = None, sync: bool = True) -> None:
        """Commit offsets for consumed messages."""
        pass

    def commit_sync(self, message: Optional[StreamMessage] = None) -> None:
        """Synchronously commit offsets for consumed messages."""
        self.commit(message=message, sync=True)

    @abstractmethod
    def close(self) -> None:
        """Release consumer resources and leave consumer group."""
        pass


# =====================================================================
# Real Kafka Drivers (confluent-kafka backed)
# =====================================================================

class KafkaStreamProducer(StreamProducer):
    """Production StreamProducer backed by confluent-kafka."""

    def __init__(self, bootstrap_servers: str, client_id: str = "sentinel-producer", **kwargs):
        import confluent_kafka
        conf = {
            "bootstrap.servers": bootstrap_servers,
            "client.id": client_id,
            "linger.ms": kwargs.get("linger_ms", 5),
            "compression.type": kwargs.get("compression_type", "lz4"),
            "queue.buffering.max.messages": kwargs.get("queue_max_messages", 100000),
        }
        self._producer = confluent_kafka.Producer(conf)

    def produce(
        self,
        topic: str,
        value: bytes,
        key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        kafka_headers = [(k, v.encode("utf-8") if isinstance(v, str) else v) for k, v in (headers or {}).items()]
        self._producer.produce(
            topic=topic,
            value=value,
            key=key.encode("utf-8") if key is not None else None,
            headers=kafka_headers if kafka_headers else None,
        )
        self._producer.poll(0)

    def flush(self, timeout: Optional[float] = None) -> int:
        return self._producer.flush(timeout if timeout is not None else -1)

    def close(self) -> None:
        self.flush(5.0)


class KafkaStreamConsumer(StreamConsumer):
    """Production StreamConsumer backed by confluent-kafka with manual offset management."""

    def __init__(
        self,
        bootstrap_servers: str,
        group_id: str,
        client_id: str = "sentinel-consumer",
        auto_offset_reset: str = "earliest",
        **kwargs,
    ):
        import confluent_kafka
        conf = {
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "client.id": client_id,
            "auto.offset.reset": auto_offset_reset,
            "enable.auto.commit": False,  # Strict manual offset management
        }
        self._consumer = confluent_kafka.Consumer(conf)
        self._subscribed_topics: List[str] = []

    def subscribe(self, topics: List[str]) -> None:
        self._subscribed_topics = list(topics)
        self._consumer.subscribe(self._subscribed_topics)

    def poll(self, timeout: float = 1.0) -> Optional[StreamMessage]:
        msg = self._consumer.poll(timeout)
        if msg is None:
            return None
        if msg.error():
            logger.warning(f"Kafka consumer error: {msg.error()}")
            return None

        headers_dict = {}
        if msg.headers():
            for k, v in msg.headers():
                headers_dict[k] = v.decode("utf-8") if isinstance(v, bytes) else str(v)

        return StreamMessage(
            topic=msg.topic(),
            partition=msg.partition(),
            offset=msg.offset(),
            key=msg.key().decode("utf-8") if msg.key() else None,
            value=msg.value(),
            headers=headers_dict,
            timestamp=msg.timestamp()[1] / 1000.0 if msg.timestamp()[0] != 0 else None,
        )

    def commit(self, message: Optional[StreamMessage] = None, sync: bool = True) -> None:
        self._consumer.commit(asynchronous=not sync)

    def close(self) -> None:
        self._consumer.close()


# =====================================================================
# In-Memory Mock Streaming Bus (100% Deterministic Offline Testing)
# =====================================================================

class MemoryStreamingBus:
    """Thread-safe in-memory message bus with topic partitioning, consumer groups, and offsets."""

    def __init__(self):
        self._lock = threading.Lock()
        # topic -> list of StreamMessage
        self._topics: Dict[str, List[StreamMessage]] = {}
        # (group_id, topic) -> committed_offset
        self._committed_offsets: Dict[Tuple[str, str], int] = {}
        # (group_id, topic) -> current_read_offset
        self._read_offsets: Dict[Tuple[str, str], int] = {}

    def produce_message(
        self,
        topic: str,
        value: bytes,
        key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        partition: int = 0,
    ) -> StreamMessage:
        with self._lock:
            if topic not in self._topics:
                self._topics[topic] = []
            offset = len(self._topics[topic])
            msg = StreamMessage(
                topic=topic,
                partition=partition,
                offset=offset,
                key=key,
                value=value,
                headers=dict(headers or {}),
            )
            self._topics[topic].append(msg)
            return msg

    def get_messages(self, topic: str) -> List[StreamMessage]:
        with self._lock:
            return list(self._topics.get(topic, []))

    def clear(self) -> None:
        with self._lock:
            self._topics.clear()
            self._committed_offsets.clear()
            self._read_offsets.clear()

    def create_producer(self) -> StreamProducer:
        return MemoryStreamProducer(self)

    def create_consumer(self, group_id: str) -> StreamConsumer:
        return MemoryStreamConsumer(self, group_id)

    def get_producer(self) -> StreamProducer:
        """Alias for create_producer."""
        return self.create_producer()

    def get_consumer(self, group_id: str) -> StreamConsumer:
        """Alias for create_consumer."""
        return self.create_consumer(group_id)


class MemoryStreamProducer(StreamProducer):
    """In-memory producer sending messages to MemoryStreamingBus."""

    def __init__(self, bus: MemoryStreamingBus):
        self.bus = bus

    def produce(
        self,
        topic: str,
        value: bytes,
        key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.bus.produce_message(topic=topic, value=value, key=key, headers=headers)

    def flush(self, timeout: Optional[float] = None) -> int:
        return 0

    def close(self) -> None:
        pass


class MemoryStreamConsumer(StreamConsumer):
    """In-memory consumer reading messages from MemoryStreamingBus by consumer group."""

    def __init__(self, bus: MemoryStreamingBus, group_id: str):
        self.bus = bus
        self.group_id = group_id
        self._subscribed_topics: List[str] = []
        self._last_polled_message: Optional[StreamMessage] = None

    def subscribe(self, topics: List[str]) -> None:
        self._subscribed_topics = list(topics)

    def poll(self, timeout: float = 1.0) -> Optional[StreamMessage]:
        with self.bus._lock:
            for topic in self._subscribed_topics:
                messages = self.bus._topics.get(topic, [])
                offset_key = (self.group_id, topic)
                current_offset = self.bus._read_offsets.get(offset_key, 0)
                if current_offset < len(messages):
                    msg = messages[current_offset]
                    self.bus._read_offsets[offset_key] = current_offset + 1
                    self._last_polled_message = msg
                    return msg
        return None

    def commit(self, message: Optional[StreamMessage] = None, sync: bool = True) -> None:
        msg = message or self._last_polled_message
        if msg is not None:
            with self.bus._lock:
                offset_key = (self.group_id, msg.topic)
                self.bus._committed_offsets[offset_key] = msg.offset + 1

    def close(self) -> None:
        pass
