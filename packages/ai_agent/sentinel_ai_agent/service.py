"""Core GenAI Security Analyst service orchestrating retrieval, generation, validation, and caching."""

import asyncio
import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from sentinel_ai_agent.base import BaseAnalystAgent
from sentinel_ai_agent.cache.memory_cache import DeterministicAnalysisCache
from sentinel_ai_agent.config import AIAnalystConfig
from sentinel_ai_agent.context.builder import AlertContextBuilder
from sentinel_ai_agent.context.sanitizer import TelemetrySanitizer
from sentinel_ai_agent.fallback.engine import DeterministicFallbackEngine
from sentinel_ai_agent.metrics import AIMetrics
from sentinel_ai_agent.prompts.templates import (
    ALERT_ANALYSIS_SYSTEM_PROMPT,
    ANALYST_QA_SYSTEM_PROMPT,
)
from sentinel_ai_agent.providers.base import BaseLLMProvider
from sentinel_ai_agent.providers.mock import MockLLMProvider
from sentinel_ai_agent.providers.openai_provider import OpenAICompatibleProvider
from sentinel_ai_agent.providers.anthropic_provider import AnthropicProvider
from sentinel_ai_agent.validators.grounding import GroundingValidator
from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AnalystQuestionResponse,
    GroundingStatus,
)
from sentinel_models.alerts import SecurityAlert
from sentinel_models.events import FlowRecord

logger = logging.getLogger("sentinel.ai.service")


class GenAIAnalystService(BaseAnalystAgent):
    """Main orchestrator for grounded advisory security analysis in SentinelAI."""

    def __init__(
        self,
        config: Optional[AIAnalystConfig] = None,
        provider: Optional[BaseLLMProvider] = None,
    ):
        self.config = config or AIAnalystConfig()
        self.provider = provider or self._init_provider(self.config)
        self.context_builder = AlertContextBuilder(max_context_tokens=self.config.max_context_tokens)
        self.cache = DeterministicAnalysisCache(
            max_entries=self.config.cache_max_entries,
            default_ttl_seconds=self.config.cache_ttl_seconds,
        )
        self.metrics = AIMetrics()
        self._in_flight_analyses: Dict[str, asyncio.Future] = {}

    @classmethod
    def _init_provider(cls, cfg: AIAnalystConfig) -> BaseLLMProvider:
        """Initialize configured provider backend."""
        p_type = cfg.provider.lower()
        if p_type == "mock":
            return MockLLMProvider(model_name=cfg.model_name)
        elif p_type in ("openai", "ollama", "vllm"):
            return OpenAICompatibleProvider(
                model_name=cfg.model_name,
                api_key=cfg.api_key,
                base_url=cfg.base_url,
                max_retries=cfg.max_retries,
                retry_backoff=cfg.retry_backoff_base,
            )
        elif p_type == "anthropic":
            return AnthropicProvider(
                model_name=cfg.model_name,
                api_key=cfg.api_key,
                base_url=cfg.base_url,
                max_retries=cfg.max_retries,
                retry_backoff=cfg.retry_backoff_base,
            )
        else:
            logger.warning("Unknown provider '%s', defaulting to MockLLMProvider", cfg.provider)
            return MockLLMProvider(model_name=cfg.model_name)

    async def analyze_alert(
        self,
        alert: SecurityAlert,
        flows: Optional[List[FlowRecord]] = None,
        mode: str = "comprehensive",
    ) -> AlertAnalysisReport:
        """Generate a grounded advisory incident report with caching, coalescing, and fallback."""
        start_time = time.time()
        last_seen_iso = alert.last_seen.isoformat() if alert.last_seen else "unknown"
        status_str = alert.status.value if hasattr(alert.status, "value") else str(alert.status)
        evidence_hash = self.cache.compute_evidence_signals_hash(alert)

        cache_key = self.cache.compute_analysis_cache_key(
            alert_id=alert.alert_id,
            last_seen_iso=last_seen_iso,
            status=status_str,
            evidence_signals_hash=evidence_hash,
            prompt_version=self.config.prompt_version,
            model_name=self.config.model_name,
            mode=mode,
        )

        # 1. Check cache
        cached = self.cache.get_analysis(cache_key)
        if cached:
            logger.info("Serving analysis report from cache for alert %s", alert.alert_id)
            return cached

        # 2. Check in-flight coalescing
        if cache_key in self._in_flight_analyses:
            logger.info("Coalescing duplicate concurrent analysis request for alert %s", alert.alert_id)
            return await self._in_flight_analyses[cache_key]

        # Create new in-flight future
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._in_flight_analyses[cache_key] = future

        try:
            # 3. Assemble grounded context
            context_dict = self.context_builder.build_analysis_context(alert, flows=flows, mode=mode)
            prompt = self.context_builder.format_prompt(context_dict)

            # 4. Invoke provider
            report: AlertAnalysisReport
            try:
                report = await self.provider.generate_structured(
                    prompt=prompt,
                    system_prompt=ALERT_ANALYSIS_SYSTEM_PROMPT,
                    response_schema=AlertAnalysisReport,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    timeout_seconds=self.config.timeout_seconds,
                )
                self.metrics.record_request(
                    success=True,
                    is_fallback=False,
                    latency_sec=time.time() - start_time,
                )
            except Exception as e:
                logger.warning(
                    "Remote LLM provider failed for alert %s (%s). Engaging deterministic fallback.",
                    alert.alert_id,
                    e,
                )
                report = DeterministicFallbackEngine.generate_fallback_report(
                    alert=alert,
                    reason=f"Provider {self.config.provider} error: {e}",
                )
                self.metrics.record_request(
                    success=True,
                    is_fallback=True,
                    latency_sec=time.time() - start_time,
                )

            # 5. Authoritative grounding validation (never silently rewrites)
            validated_report = GroundingValidator.validate_alert_report(report, alert, flows=flows)
            if validated_report.validation_log.validation_status == GroundingStatus.FLAGGED_UNGROUNDED:
                self.metrics.record_grounding_violation()

            # 6. Put in cache
            self.cache.put_analysis(cache_key, validated_report)

            future.set_result(validated_report)
            return validated_report

        except Exception as e:
            if not future.done():
                future.set_exception(e)
            self.metrics.record_request(success=False, latency_sec=time.time() - start_time)
            raise e
        finally:
            self._in_flight_analyses.pop(cache_key, None)

    async def ask_question(
        self,
        alert: SecurityAlert,
        question: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> AnalystQuestionResponse:
        """Answer an analyst inquiry grounded strictly in the alert telemetry."""
        start_time = time.time()
        safe_question = TelemetrySanitizer.sanitize_analyst_question(question, max_length=self.config.max_question_length)
        last_seen_iso = alert.last_seen.isoformat() if alert.last_seen else "unknown"
        evidence_hash = self.cache.compute_evidence_signals_hash(alert)

        # Compute history hash
        hist_str = ""
        if conversation_history:
            hist_str = "|".join(f"{h.get('role')}:{h.get('content')}" for h in conversation_history[-4:])
        history_hash = hashlib.sha256(hist_str.encode("utf-8")).hexdigest()[:16]

        qa_cache_key = self.cache.compute_qa_cache_key(
            alert_id=alert.alert_id,
            last_seen_iso=last_seen_iso,
            evidence_signals_hash=evidence_hash,
            normalized_question=safe_question,
            conversation_history_hash=history_hash,
            prompt_version=self.config.prompt_version,
            model_name=self.config.model_name,
        )

        # 1. Check cache
        cached = self.cache.get_qa(qa_cache_key)
        if cached:
            logger.info("Serving Q&A answer from cache for alert %s", alert.alert_id)
            return cached

        # 2. Build prompt
        context_dict = self.context_builder.build_analysis_context(alert)
        prompt = self.context_builder.format_qa_prompt(context_dict, question=safe_question, history=conversation_history)

        # 3. Invoke provider or fallback
        response: AnalystQuestionResponse
        try:
            response = await self.provider.generate_structured(
                prompt=prompt,
                system_prompt=ANALYST_QA_SYSTEM_PROMPT,
                response_schema=AnalystQuestionResponse,
                temperature=self.config.qa_temperature,
                max_tokens=self.config.max_tokens,
                timeout_seconds=self.config.timeout_seconds,
            )
            self.metrics.record_request(success=True, is_fallback=False, latency_sec=time.time() - start_time)
        except Exception as e:
            logger.warning("Provider Q&A failed for alert %s (%s). Generating fallback answer.", alert.alert_id, e)
            response = DeterministicFallbackEngine.generate_fallback_qa(
                alert=alert,
                question=safe_question,
                reason=f"Provider error: {e}",
            )
            self.metrics.record_request(success=True, is_fallback=True, latency_sec=time.time() - start_time)

        # 4. Validate Q&A grounding
        validated_resp = GroundingValidator.validate_qa_response(response, alert)

        # 5. Put in cache
        self.cache.put_qa(qa_cache_key, validated_resp)
        return validated_resp

    def get_cached_analysis_by_key(self, cache_key: str) -> Optional[AlertAnalysisReport]:
        """Direct cache lookup by key."""
        return self.cache.get_analysis(cache_key)

    async def check_health(self) -> Dict[str, Any]:
        """Return provider status, cache stats, and request metrics."""
        provider_health = await self.provider.check_health()
        return {
            "status": "healthy",
            "provider": provider_health,
            "cache": self.cache.get_stats(),
            "metrics": self.metrics.get_summary(),
            "config": {
                "model_name": self.config.model_name,
                "prompt_version": self.config.prompt_version,
                "rate_limit_rpm": self.config.rate_limit_rpm,
                "timeout_seconds": self.config.timeout_seconds,
            },
        }
