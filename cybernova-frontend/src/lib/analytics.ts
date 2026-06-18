/**
 * CyberNova - Analytics / Event Tracking
 * Tracks onboarding funnel metrics for conversion optimization
 */

import { config } from '../config';

// Event types
export type OnboardingEvent =
  | 'signup_completed'
  | 'org_created'
  | 'org_key_viewed'
  | 'org_key_copied'
  | 'agent_downloaded'
  | 'agent_command_copied'
  | 'terms_accepted'
  | 'agent_started'
  | 'device_waiting'
  | 'device_connected'
  | 'dashboard_viewed'
  | 'onboarding_completed';

export type ConversionEvent =
  | 'demo_started'
  | 'demo_completed'
  | 'device_added'
  | 'alert_triggered'
  | 'device_isolated';

// Track timing
const eventTimestamps: Record<string, number> = {};

// Get or create device ID
const getDeviceId = (): string => {
  let deviceId = localStorage.getItem('cybernova_device_id');
  if (!deviceId) {
    deviceId = `device_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    localStorage.setItem('cybernova_device_id', deviceId);
  }
  return deviceId;
};

/**
 * Track an onboarding event with timing
 */
export function trackOnboardingEvent(
  event: OnboardingEvent,
  metadata?: Record<string, any>
) {
  const timestamp = Date.now();
  eventTimestamps[event] = timestamp;

  // Store in localStorage for persistence
  const events = JSON.parse(localStorage.getItem('cybernova_onboarding_events') || '{}');
  events[event] = {
    timestamp,
    metadata,
    deviceId: getDeviceId(),
  };
  localStorage.setItem('cybernova_onboarding_events', JSON.stringify(events));

  // Debug log (dev only)
  if (config.debug) console.log(`[Analytics] ${event}`, metadata || {});

  // In production, send to analytics service
  // Example: mixpanel.track(event, metadata);
}

/**
 * Track a conversion event
 */
export function trackConversionEvent(
  event: ConversionEvent,
  metadata?: Record<string, any>
) {
  if (config.debug) console.log(`[Analytics] ${event}`, metadata || {});
  
  // In production, send to analytics service
}
