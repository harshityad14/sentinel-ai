import { useState, useEffect, useCallback } from "react";
import {
  fetchAlertAnalysis,
  getCachedAlertAnalysis,
  askAnalystQuestion,
} from "../api/ai_analyst";
import type { AlertAnalysisReport, EvidenceCitation } from "../types/ai_analyst";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  citations?: EvidenceCitation[];
  isGrounded?: boolean;
  uncertainty?: string | null;
}

export function useAIAnalyst(alertId: string | null) {
  const [report, setReport] = useState<AlertAnalysisReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);

  // Check for cached analysis when alertId changes
  useEffect(() => {
    let isMounted = true;
    if (!alertId) {
      setReport(null);
      setChatMessages([]);
      return;
    }

    async function checkCached() {
      try {
        const cached = await getCachedAlertAnalysis(alertId!);
        if (isMounted) {
          setReport(cached);
          setError(null);
        }
      } catch {
        // Cache miss is normal; keep report null so user can click "Generate"
        if (isMounted) {
          setReport(null);
        }
      }
    }

    setChatMessages([]);
    setError(null);
    setChatError(null);
    checkCached();

    return () => {
      isMounted = false;
    };
  }, [alertId]);

  const analyze = useCallback(async () => {
    if (!alertId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAlertAnalysis(alertId);
      setReport(data);
    } catch (err: any) {
      setError(err?.message || "Failed to generate AI security analysis");
    } finally {
      setLoading(false);
    }
  }, [alertId]);

  const ask = useCallback(
    async (question: string) => {
      if (!alertId || !question.trim()) return;
      setChatLoading(true);
      setChatError(null);

      const userMsg: ChatMessage = { role: "user", content: question.trim() };
      setChatMessages((prev) => [...prev, userMsg]);

      try {
        const history = chatMessages.map((m) => ({
          role: m.role,
          content: m.content,
        }));
        const resp = await askAnalystQuestion(alertId, question.trim(), history);
        const assistantMsg: ChatMessage = {
          role: "assistant",
          content: resp.answer,
          citations: resp.evidence_citations,
          isGrounded: resp.grounded_in_telemetry,
          uncertainty: resp.uncertainty_notes,
        };
        setChatMessages((prev) => [...prev, assistantMsg]);
      } catch (err: any) {
        setChatError(err?.message || "Failed to answer analyst inquiry");
      } finally {
        setChatLoading(false);
      }
    },
    [alertId, chatMessages]
  );

  return {
    report,
    loading,
    error,
    analyze,
    chatMessages,
    chatLoading,
    chatError,
    ask,
  };
}
