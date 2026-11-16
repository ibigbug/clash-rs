import { useEffect, useState } from 'react';
import { useWebSocket } from './useWebSocket';
import { getWsUrl } from '../lib/api';

export interface FlowSource {
  ip: string;
  /** Inbound the connections arrived through: "HTTP", "HTTP-CONNECT", "SOCKS5", "TUN", ... */
  inbound: string;
}

export interface FlowRecord {
  dstHost: string;
  dstPort: number;
  protocol: string;
  srcIps: string[];
  /** Absent from older cores. */
  sources?: FlowSource[];
  connCount: number;
  activeCount: number;
  closedCount: number;
  uploadTotal: number;
  downloadTotal: number;
  bytesTotal: number;
  rule: string;
  rulePayload: string;
  chains: string[];
  asn: string | null;
  country: string | null;
  lastSeen: string;
}

interface UseFlowsReturn {
  flows: FlowRecord[];
  readyState: import('./useWebSocket').ReadyState;
}

export function useFlows(includeClosed = true): UseFlowsReturn {
  const url = getWsUrl(`/ws/flows?interval=5&top=50&include_closed=${includeClosed}`);
  const { lastMessage, readyState } = useWebSocket<FlowRecord[]>(url);

  const [flows, setFlows] = useState<FlowRecord[]>([]);

  useEffect(() => {
    if (!lastMessage) return;
    setFlows(lastMessage);
  }, [lastMessage]);

  return { flows, readyState };
}
