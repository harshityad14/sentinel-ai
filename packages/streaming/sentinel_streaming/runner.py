"""Unified streaming pipeline worker runner.

Orchestrates the 4 SentinelAI Kafka stream workers concurrently:
1. FlowFeatureWorker: sentinel.flows.raw -> sentinel.flows.features
2. FeatureDetectionWorker: sentinel.flows.features -> sentinel.detections.raw
3. DetectionCorrelationWorker: sentinel.detections.raw -> sentinel.alerts.correlated
4. AlertPersistenceWorker: sentinel.alerts.correlated -> PostgreSQL / Database Sink
"""

import logging
import os
import signal
import sys
import threading
import time
from typing import List, Optional

from sentinel_streaming.bus import (
    KafkaStreamConsumer,
    KafkaStreamProducer,
    MemoryStreamingBus,
    StreamConsumer,
    StreamProducer,
)
from sentinel_streaming.topics import (
    TOPIC_ALERTS_CORRELATED,
    TOPIC_DETECTIONS_RAW,
    TOPIC_FLOWS_FEATURES,
    TOPIC_FLOWS_RAW,
)
from sentinel_streaming.workers.alert_persistence_worker import AlertPersistenceWorker
from sentinel_streaming.workers.base import BaseStreamWorker
from sentinel_streaming.workers.detection_correlation_worker import DetectionCorrelationWorker
from sentinel_streaming.workers.feature_detection_worker import FeatureDetectionWorker
from sentinel_streaming.workers.flow_feature_worker import FlowFeatureWorker

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("sentinel.streaming.runner")


class StreamingPipelineRunner:
    """Manages the lifecycle of all streaming workers in a single process."""

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        database_url: Optional[str] = None,
        use_memory_bus: bool = False,
    ):
        self.bootstrap_servers = bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

        db_url = database_url or os.getenv("DATABASE_URL")
        if not db_url or db_url.startswith("sqlite"):
            pg_host = os.getenv("POSTGRES_HOST")
            if pg_host:
                pg_user = os.getenv("POSTGRES_USER", "sentinel")
                pg_pass = os.getenv("POSTGRES_PASSWORD", "")
                pg_port = os.getenv("POSTGRES_PORT", "5432")
                pg_db = os.getenv("POSTGRES_DB", "sentinel_db")
                db_url = f"postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}"
            else:
                db_url = db_url or "sqlite:///./sentinel.db"
        self.database_url = db_url

        self.use_memory_bus = use_memory_bus

        self.workers: List[BaseStreamWorker] = []
        self.threads: List[threading.Thread] = []
        self._stop_event = threading.Event()
        self._session_factory = None

        self._init_database()
        self._init_workers()

    def _init_database(self):
        """Initialize database connection sessionmaker if database_url is provided."""
        if not self.database_url:
            return

        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker

            engine = create_engine(
                self.database_url,
                pool_pre_ping=True,
                pool_recycle=1800,
            )
            self._session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            logger.info("Database session factory initialized for AlertPersistenceWorker")
        except Exception as exc:
            logger.warning(f"Could not initialize database engine for streaming runner: {exc}")
            self._session_factory = None

    def _create_consumer(self, group_id: str) -> StreamConsumer:
        if self.use_memory_bus:
            bus = MemoryStreamingBus()
            return bus.get_consumer(group_id)
        return KafkaStreamConsumer(
            bootstrap_servers=self.bootstrap_servers,
            group_id=group_id,
            auto_offset_reset="earliest",
        )

    def _create_producer(self) -> StreamProducer:
        if self.use_memory_bus:
            bus = MemoryStreamingBus()
            return bus.get_producer()
        return KafkaStreamProducer(bootstrap_servers=self.bootstrap_servers)

    def _init_workers(self):
        """Instantiate all 4 streaming pipeline workers."""
        logger.info(f"Initializing streaming workers against Kafka: {self.bootstrap_servers}")

        # Shared producer for stages that publish to Kafka
        producer = self._create_producer()

        # 1. Flow -> Feature Worker
        c1 = self._create_consumer("sentinel-flow-feature-workers")
        w1 = FlowFeatureWorker(
            consumer=c1,
            producer=producer,
            input_topic=TOPIC_FLOWS_RAW,
            output_topic=TOPIC_FLOWS_FEATURES,
        )

        # 2. Feature -> Detection Worker
        c2 = self._create_consumer("sentinel-feature-detection-workers")
        w2 = FeatureDetectionWorker(
            consumer=c2,
            producer=producer,
            input_topic=TOPIC_FLOWS_FEATURES,
            output_topic=TOPIC_DETECTIONS_RAW,
        )

        # 3. Detection -> Correlation Worker
        c3 = self._create_consumer("sentinel-correlation-workers")
        w3 = DetectionCorrelationWorker(
            consumer=c3,
            producer=producer,
            input_topic=TOPIC_DETECTIONS_RAW,
            output_topic=TOPIC_ALERTS_CORRELATED,
        )

        # 4. Correlation -> Alert Persistence Sink Worker
        c4 = self._create_consumer("sentinel-alert-persistence-workers")
        w4 = AlertPersistenceWorker(
            consumer=c4,
            session_factory=self._session_factory,
            input_topic=TOPIC_ALERTS_CORRELATED,
        )

        self.workers = [w1, w2, w3, w4]

    def start(self):
        """Start all workers in background threads."""
        logger.info(f"Starting {len(self.workers)} streaming pipeline workers...")
        self._stop_event.clear()

        for worker in self.workers:
            t = threading.Thread(
                target=worker.run_poll_loop,
                kwargs={"poll_timeout": 1.0},
                name=f"worker-{worker.worker_name}",
                daemon=True,
            )
            t.start()
            self.threads.append(t)

        logger.info("All streaming workers active and polling topics")

    def stop(self):
        """Signal all workers to halt and await thread completion."""
        logger.info("Stopping all streaming workers...")
        self._stop_event.set()

        for worker in self.workers:
            try:
                worker.stop()
            except Exception as e:
                logger.warning(f"Error stopping worker {worker.worker_name}: {e}")

        for t in self.threads:
            t.join(timeout=5.0)

        logger.info("All streaming workers stopped successfully")

    def run_forever(self):
        """Block main thread until interrupt or termination signal."""
        self.start()

        def _signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        try:
            while not self._stop_event.is_set():
                time.sleep(1.0)
        except (KeyboardInterrupt, SystemExit):
            self.stop()


def main():
    runner = StreamingPipelineRunner()
    runner.run_forever()


if __name__ == "__main__":
    main()
