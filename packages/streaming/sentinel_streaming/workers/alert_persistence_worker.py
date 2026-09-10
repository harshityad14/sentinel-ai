"""Alert Persistence Worker consuming correlated alerts and writing to PostgreSQL/TimescaleDB sink."""

import logging
from typing import Any, Callable, Optional

from sentinel_models.alerts import SecurityAlert
from sentinel_streaming.bus import StreamConsumer
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import TOPIC_ALERTS_CORRELATED
from sentinel_streaming.workers.base import BaseStreamWorker

logger = logging.getLogger(__name__)


class AlertPersistenceWorker(BaseStreamWorker[SecurityAlert, Any]):
    """Terminal stream sink worker persisting validated security alerts to database storage."""

    def __init__(
        self,
        consumer: StreamConsumer,
        session_factory: Optional[Callable[[], Any]] = None,
        input_topic: str = TOPIC_ALERTS_CORRELATED,
        **kwargs,
    ) -> None:
        super().__init__(
            consumer=consumer,
            producer=None,
            model_class=SecurityAlert,
            input_topic=input_topic,
            output_topic=None,
            worker_name="AlertPersistenceWorker",
            **kwargs,
        )
        self.session_factory = session_factory
        self.persisted_count: int = 0

    def process_envelope(self, envelope: StreamEnvelope[SecurityAlert]) -> Optional[StreamEnvelope[Any]]:
        """Persist alert into SQL repository idempotently and commit the database transaction."""
        alert = envelope.payload

        if self.session_factory is None:
            # Standalone or test mode without database connection
            logger.info(f"Persisted alert (in-memory sink): {alert.alert_id} (Threat: {alert.threat_class})")
            self.persisted_count += 1
            return None

        session = self.session_factory()
        try:
            from app.repositories.alert_repo import AlertRepository

            repo = AlertRepository(session)
            existing = repo.get_by_alert_id(alert.alert_id)
            if existing:
                # Update existing record
                logger.debug(f"Updating existing persisted alert {alert.alert_id}")
                if hasattr(alert, "last_seen"):
                    from datetime import datetime
                    dt = (
                        datetime.fromtimestamp(alert.last_seen)
                        if isinstance(alert.last_seen, (int, float))
                        else alert.last_seen
                    )
                    existing.last_seen = dt
                if hasattr(alert, "risk_score"):
                    score_val = (
                        float(alert.risk_score.score)
                        if hasattr(alert.risk_score, "score")
                        else float(alert.risk_score)
                    )
                    existing.risk_score = score_val
            else:
                repo.create_alert(alert)

            session.commit()
            self.persisted_count += 1
            logger.debug(f"Persisted alert to database: {alert.alert_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to persist alert {alert.alert_id} to database: {e}")
            raise
        finally:
            if hasattr(session, "close"):
                session.close()

        return None
