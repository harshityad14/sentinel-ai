import { request } from "./client";
import type {
  AlertAnalysisReport,
  AnalystQuestionRequest,
  AnalystQuestionResponse,
  AIHealthResponse,
} from "../types/ai_analyst";

/**
 * Triggers on-demand grounded security analysis for an alert.
 */
export async function fetchAlertAnalysis(alertId: string): Promise<AlertAnalysisReport> {
  return request<AlertAnalysisReport>(
    `/alerts/${encodeURIComponent(alertId)}/analyze`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    }
  );
}

/**
 * Retrieves cached analysis report if previously generated.
 */
export async function getCachedAlertAnalysis(alertId: string): Promise<AlertAnalysisReport> {
  return request<AlertAnalysisReport>(
    `/alerts/${encodeURIComponent(alertId)}/analysis`
  );
}

/**
 * Submits an analyst question regarding the alert's telemetry.
 */
export async function askAnalystQuestion(
  alertId: string,
  question: string,
  history?: Array<{ role: string; content: string }>
): Promise<AnalystQuestionResponse> {
  const payload: AnalystQuestionRequest = {
    question,
    conversation_history: history,
  };
  return request<AnalystQuestionResponse>(
    `/alerts/${encodeURIComponent(alertId)}/ask`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );
}

/**
 * Fetches GenAI Security Analyst health, provider status, and metrics.
 */
export async function fetchAIHealth(): Promise<AIHealthResponse> {
  return request<AIHealthResponse>("/ai/health");
}
