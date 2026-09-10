import React, { useState } from 'react';
import type { AlertStatus } from '../../types/alert';
import { Modal } from '../common/Modal';

interface LifecycleModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentStatus: AlertStatus;
  alertId: string;
  onUpdateStatus: (newStatus: AlertStatus, operatorName: string, notes: string) => Promise<void>;
}

export const LifecycleModal: React.FC<LifecycleModalProps> = ({
  isOpen,
  onClose,
  currentStatus,
  alertId,
  onUpdateStatus,
}) => {
  const [operator, setOperator] = useState('');
  const [notes, setNotes] = useState('');
  const [targetStatus, setTargetStatus] = useState<AlertStatus>(
    currentStatus === 'NEW' ? 'ACKNOWLEDGED' : 'RESOLVED'
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!operator.trim()) {
      setError('Operator name is required.');
      return;
    }
    if (!notes.trim()) {
      setError('Investigation notes are required.');
      return;
    }

    try {
      setSubmitting(true);
      setError(null);
      await onUpdateStatus(targetStatus, operator.trim(), notes.trim());
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to update alert lifecycle.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Update Alert Lifecycle: ${alertId.slice(0, 16)}...`}>
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {error && (
          <div style={{ color: 'var(--danger)', fontSize: '0.85rem', background: 'rgba(239, 68, 68, 0.1)', padding: '0.5rem', borderRadius: '4px' }}>
            {error}
          </div>
        )}

        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Target Lifecycle State
          </label>
          <select
            value={targetStatus}
            onChange={(e) => setTargetStatus(e.target.value as AlertStatus)}
            style={{
              width: '100%',
              padding: '0.5rem',
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              color: 'var(--text-main)',
            }}
          >
            {currentStatus !== 'NEW' && <option value="NEW">NEW (Reopen)</option>}
            <option value="ACKNOWLEDGED">ACKNOWLEDGED (Under Investigation)</option>
            <option value="RESOLVED">RESOLVED (Threat Contained / Remediated)</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE (Benign Anomaly)</option>
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            SOC Operator / Analyst ID *
          </label>
          <input
            type="text"
            required
            placeholder="e.g. sec-analyst-01"
            value={operator}
            onChange={(e) => setOperator(e.target.value)}
            style={{
              width: '100%',
              padding: '0.5rem',
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              color: 'var(--text-main)',
            }}
          />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Audit / Investigation Notes *
          </label>
          <textarea
            required
            rows={4}
            placeholder="Document threat verification, scope, and passive triage context..."
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            style={{
              width: '100%',
              padding: '0.5rem',
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              color: 'var(--text-main)',
              resize: 'vertical',
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '0.5rem 1rem',
              background: 'transparent',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              color: 'var(--text-muted)',
              cursor: 'pointer',
            }}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            style={{
              padding: '0.5rem 1rem',
              background: 'var(--primary)',
              border: 'none',
              borderRadius: '6px',
              color: 'white',
              cursor: submitting ? 'not-allowed' : 'pointer',
              fontWeight: 600,
            }}
          >
            {submitting ? 'Updating...' : 'Commit Status'}
          </button>
        </div>
      </form>
    </Modal>
  );
};
