/**
 * CyberNova — Frontend Configuration
 *
 * Central configuration for API endpoints, debug logging, and default thresholds.
 * In production, these values can be overridden via environment variables at build time.
 */

const DEFAULT_API_BASE_URL = '';

export const config = {
  /**
   * Base URL for the CyberNova backend API.
   * When empty (default), the frontend makes same-origin API calls through the nginx reverse proxy.
   * In development mode with Vite, set this to 'http://localhost:8000' or use Vite's proxy config.
   */
  apiBaseUrl: (import.meta as any).env?.VITE_API_BASE_URL || DEFAULT_API_BASE_URL || '',

  /**
   * Enable verbose debug logging to the browser console.
   * Automatically enabled in development, disabled in production builds.
   */
  debug: (import.meta as any).env?.VITE_DEBUG === 'true' || (import.meta as any).env?.DEV === true || false,

  /**
   * Default alert severity thresholds (0-100).
   * These map to the severity level assigned based on risk score.
   */
  alertThresholds: {
    low: 25,
    medium: 50,
    high: 75,
    critical: 90,
  } as Record<string, number>,
};
