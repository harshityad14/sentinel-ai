import React, { useState } from 'react';
import type { ChatMessage } from '../../hooks/useAIAnalyst';

interface AnalystChatProps {
  messages: ChatMessage[];
  loading: boolean;
  error: string | null;
  onSendMessage: (question: string) => void;
}

export const AnalystChat: React.FC<AnalystChatProps> = ({
  messages,
  loading,
  error,
  onSendMessage,
}) => {
  const [input, setInput] = useState('');

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;
    onSendMessage(input.trim());
    setInput('');
  };

  const quickPrompts = [
    'What was the observed packet rate?',
    'Could this incident be a false positive?',
    'Which ports and protocols were targeted?',
  ];

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '0.75rem',
        background: 'var(--bg-card)',
        padding: '1.25rem',
        borderRadius: '8px',
        border: '1px solid var(--border)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
          Interactive Analyst Q&A
        </h4>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Grounded in Alert Telemetry
        </span>
      </div>

      {/* Quick Prompts */}
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
        {quickPrompts.map((qp, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => onSendMessage(qp)}
            disabled={loading}
            style={{
              fontSize: '0.75rem',
              padding: '0.25rem 0.6rem',
              borderRadius: '12px',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              color: 'var(--text-muted)',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            {qp}
          </button>
        ))}
      </div>

      {/* Message Thread */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '0.6rem',
          maxHeight: '320px',
          overflowY: 'auto',
          padding: '0.5rem 0',
        }}
      >
        {messages.length === 0 ? (
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic', textAlign: 'center', padding: '1rem' }}>
            Ask questions about the observed telemetry, feature breaches, or detection signals.
          </div>
        ) : (
          messages.map((msg, i) => (
            <div
              key={i}
              style={{
                alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '85%',
                background: msg.role === 'user' ? '#2563eb' : 'var(--bg-surface)',
                color: msg.role === 'user' ? '#ffffff' : 'var(--text-main)',
                padding: '0.6rem 0.85rem',
                borderRadius: '8px',
                border: msg.role === 'user' ? 'none' : '1px solid var(--border)',
                fontSize: '0.85rem',
                lineHeight: 1.4,
              }}
            >
              <div>{msg.content}</div>

              {/* Citations if assistant response */}
              {msg.citations && msg.citations.length > 0 && (
                <div style={{ marginTop: '0.4rem', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '0.3rem', fontSize: '0.75rem' }}>
                  <span style={{ color: msg.role === 'user' ? '#bfdbfe' : 'var(--text-muted)' }}>Citations: </span>
                  {msg.citations.map((c, ci) => (
                    <span
                      key={ci}
                      style={{
                        marginRight: '0.4rem',
                        padding: '0.1rem 0.35rem',
                        borderRadius: '4px',
                        background: 'rgba(0, 0, 0, 0.2)',
                        fontFamily: 'monospace',
                        color: msg.role === 'user' ? '#ffffff' : '#60a5fa',
                      }}
                    >
                      {c.citation_id}: {c.feature_name || c.detector_name}
                    </span>
                  ))}
                </div>
              )}

              {msg.uncertainty && (
                <div style={{ marginTop: '0.3rem', fontSize: '0.75rem', color: '#fbbf24', fontStyle: 'italic' }}>
                  Note: {msg.uncertainty}
                </div>
              )}
            </div>
          ))
        )}

        {loading && (
          <div
            style={{
              alignSelf: 'flex-start',
              background: 'var(--bg-surface)',
              color: 'var(--text-muted)',
              padding: '0.5rem 0.85rem',
              borderRadius: '8px',
              border: '1px solid var(--border)',
              fontSize: '0.8rem',
              fontStyle: 'italic',
            }}
          >
            Analyzing telemetry...
          </div>
        )}
      </div>

      {error && (
        <div style={{ fontSize: '0.8rem', color: '#f87171', padding: '0.4rem', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '4px' }}>
          {error}
        </div>
      )}

      {/* Input Form */}
      <form onSubmit={handleSend} style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask a question about this incident (max 500 chars)..."
          maxLength={500}
          disabled={loading}
          style={{
            flex: 1,
            padding: '0.5rem 0.75rem',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            color: 'var(--text-main)',
            fontSize: '0.85rem',
            outline: 'none',
          }}
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          style={{
            padding: '0.5rem 1rem',
            background: '#2563eb',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            fontSize: '0.85rem',
            fontWeight: 500,
            cursor: !input.trim() || loading ? 'not-allowed' : 'pointer',
            opacity: !input.trim() || loading ? 0.6 : 1,
          }}
        >
          Send
        </button>
      </form>
    </div>
  );
};
