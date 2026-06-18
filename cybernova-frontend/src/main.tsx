import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { Component, type ReactNode } from "react";
import "./index.css";
import App from "./App";

/**
 * Top-level error boundary — catches ANY error in the app (including login page,
 * loading screen, hooks) and shows a visible error instead of blank white.
 */
interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class RootErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    console.error('[RootErrorBoundary]', error);
  }

  render() {
    if (this.state.hasError && this.state.error) {
      return (
        <div style={{ minHeight: '100vh', background: '#0a0e1a', color: '#e2e8f0', padding: '2rem', fontFamily: 'monospace' }}>
          <h1 style={{ color: '#ff4d4d', fontSize: '1.5rem' }}>⚠ CyberNova crashed</h1>
          <pre style={{ background: '#111827', padding: '1rem', borderRadius: '8px', marginTop: '1rem', overflow: 'auto', fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
            {this.state.error.message}

{this.state.error.stack}
          </pre>
          <button
            onClick={() => { localStorage.clear(); window.location.reload(); }}
            style={{ marginTop: '1rem', padding: '0.75rem 1.5rem', background: '#69E5FF', color: '#000', border: 'none', borderRadius: '8px', cursor: 'pointer', fontWeight: 'bold' }}
          >
            Clear Data & Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById("root")!).render(
  <RootErrorBoundary>
    <BrowserRouter basename="/app">
      <App />
    </BrowserRouter>
  </RootErrorBoundary>
);
