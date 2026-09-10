/**
 * WebSocket messaging and connection status types.
 */

import { SecurityAlertRead } from "./alert";

export type WebSocketConnectionStatus =
  | "CONNECTED"
  | "CONNECTING"
  | "RECONNECTING"
  | "DISCONNECTED"
  | "POLLING_FALLBACK";

export interface WebSocketMessage {
  type: "CONNECTED" | "NEW_ALERT" | "PING" | "PONG";
  status?: string;
  message?: string;
  data?: SecurityAlertRead;
}
