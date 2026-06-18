/**
 * CyberNova — Real-Time WebSocket Hook
 * Connects to backend WebSocket for live updates.
 *
 * Production guarantees:
 *  - Stable connect/disconnect (no reconnect storm)
 *  - Exponential backoff on reconnect
 *  - Single socket per tab
 *  - Clean disconnect on unmount
 */
import { useEffect, useRef, useState, useCallback } from 'react';
import { config } from '../config';

export interface WebSocketMessage {
  type: 'connected' | 'new_alert' | 'alert_updated' | 'new_incident' | 'incident_updated' | 'soar_action' | 'pipeline_status' | 'system_notification' | 'pong';
  data?: any;
  timestamp?: string;
  tenant_id?: string;
}

export interface UseWebSocketOptions {
  token?: string;
  tenantId?: string;
  onMessage?: (message: WebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

// Global flag: disable polling when WS is active
let _wsActive = false;
export function setWsActive(active: boolean) { _wsActive = active; }
export function isWsActive() { return _wsActive; }

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    token,
    tenantId,
    onMessage,
    onConnect,
    onDisconnect,
    onError,
    reconnectInterval = 5000,
    maxReconnectAttempts = 10,
  } = options;

  // Store callbacks in refs so connect/disconnect are stable (no reconnect storm)
  const onMessageRef = useRef(onMessage);
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);
  const onErrorRef = useRef(onError);

  useEffect(() => {
    onMessageRef.current = onMessage;
    onConnectRef.current = onConnect;
    onDisconnectRef.current = onDisconnect;
    onErrorRef.current = onError;
  }, [onMessage, onConnect, onDisconnect, onError]);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectCountRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [pipelineStatus, setPipelineStatus] = useState<any>(null);

  const connect = useCallback(() => {
    // Don't attempt WebSocket connection without a token — avoids 403 errors
    // on login page and unnecessary connection attempts before auth
    if (!token) {
      if (config.debug) console.log('[WS] Skipping connection: no auth token available');
      return;
    }

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const params = new URLSearchParams();
    if (tenantId) params.append('tenant_id', tenantId);

    const url = `${protocol}//${host}/ws${params.toString() ? '?' + params.toString() : ''}`;

    try {
      const protocols: string[] = [];
      if (token) protocols.push(token);
      wsRef.current = protocols.length > 0 ? new WebSocket(url, protocols) : new WebSocket(url);

      wsRef.current.onopen = () => {
        if (config.debug) console.log('[WS] Connected');
        setIsConnected(true);
        setWsActive(true);
        reconnectCountRef.current = 0;
        onConnectRef.current?.();

        // Subscribe to all event types
        wsRef.current?.send(JSON.stringify({
          type: 'subscribe',
          events: ['new_alert', 'alert_updated', 'new_incident', 'incident_updated', 'soar_action', 'pipeline_status'],
        }));
      };

      wsRef.current.onclose = (event) => {
        if (config.debug) console.log('[WS] Disconnected', event.code, event.reason);
        setIsConnected(false);
        setWsActive(false);
        onDisconnectRef.current?.();

        // Don't reconnect on authentication failures (4001 = auth required, 4003 = forbidden)
        if (event.code === 4001 || event.code === 4003) {
          if (config.debug) console.log('[WS] Auth error — not reconnecting');
          return;
        }

        // Exponential backoff: 5s, 10s, 20s, 40s, ...
        if (reconnectCountRef.current < maxReconnectAttempts) {
          reconnectCountRef.current += 1;
          const delay = Math.min(reconnectInterval * Math.pow(1.5, reconnectCountRef.current - 1), 30000);
          if (config.debug) console.log(`[WS] Reconnecting in ${delay}ms (${reconnectCountRef.current}/${maxReconnectAttempts})`);
          reconnectTimeoutRef.current = setTimeout(connect, delay);
        }
      };

      wsRef.current.onerror = (error) => {
        if (config.debug) console.debug('[WS] Connection error (non-fatal)');
        onErrorRef.current?.(error);
      };

      wsRef.current.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);

          // SECURITY: Tenant isolation filter
          if (tenantId && message.tenant_id && message.tenant_id !== tenantId) {
            if (config.debug) console.debug('[WS] Filtered: wrong tenant', message.tenant_id);
            return;
          }

          setLastMessage(message);

          // Handle different message types
          switch (message.type) {
            case 'connected':
              if (config.debug) console.log('[WS] Authenticated');
              break;

            case 'new_alert':
              setAlerts(prev => [message.data?.alert, ...prev].slice(0, 100));
              break;

            case 'alert_updated':
              setAlerts(prev => prev.map(a =>
                (a.alert_id === message.data?.alert?.alert_id) ? message.data.alert : a
              ));
              break;

            case 'new_incident':
              setIncidents(prev => [message.data?.incident, ...prev].slice(0, 50));
              break;

            case 'incident_updated':
              setIncidents(prev => prev.map(i =>
                (i.incident_id === message.data?.incident?.incident_id) ? message.data.incident : i
              ));
              break;

            case 'soar_action':
              if (config.debug) console.log('[WS] SOAR action:', message.data?.action);
              break;

            case 'pipeline_status':
              setPipelineStatus(message.data);
              break;

            case 'pong':
              break;
          }

          onMessageRef.current?.(message);
        } catch (error) {
          if (config.debug) console.error('[WS] Parse error:', error);
        }
      };
    } catch (error) {
      if (config.debug) console.error('[WS] Connection error:', error);
    }
  }, [token, tenantId, maxReconnectAttempts, reconnectInterval]); // STABLE — no callback deps

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
    setWsActive(false);
  }, []);

  const sendMessage = useCallback((message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  }, []);

  const unsubscribe = useCallback((events: string[]) => {
    sendMessage({ type: 'unsubscribe', events });
  }, [sendMessage]);

  const requestStatus = useCallback(() => {
    sendMessage({ type: 'get_status' });
  }, [sendMessage]);

  // Connect once, disconnect on unmount — stable deps
  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return {
    isConnected,
    lastMessage,
    alerts,
    incidents,
    pipelineStatus,
    connect,
    disconnect,
    sendMessage,
    unsubscribe,
    requestStatus,
  };
}
