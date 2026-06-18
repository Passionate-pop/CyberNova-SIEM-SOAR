/**
 * CyberNova — Web Page Configuration
 *
 * Central configuration for linking to the CyberNova app (cybernova-frontend).
 * In development, the app runs on port 5173. In production, set
 * NEXT_PUBLIC_APP_URL to your deployed app domain.
 */

export const appConfig = {
  /** Base URL for the CyberNova app — relative path when served from same origin via nginx. */
  appUrl:
    (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_APP_URL) || "/app/",

  /** Direct link to the app's login/auth page. */
  get loginUrl() {
    return `${this.appUrl}`;
  },

  /** Direct link to the app's register/auth page. */
  get registerUrl() {
    return `${this.appUrl}`;
  },
};
