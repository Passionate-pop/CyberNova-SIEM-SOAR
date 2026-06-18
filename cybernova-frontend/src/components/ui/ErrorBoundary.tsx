import { Component, type ReactNode, type ErrorInfo } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[ErrorBoundary] Uncaught error:', error, errorInfo);
    this.props.onError?.(error, errorInfo);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] p-8 text-center">
          <div className="flex items-center justify-center w-16 h-16 rounded-full bg-red-500/10 mb-4">
            <AlertTriangle size={32} className="text-red-400" />
          </div>
          <h2 className="text-lg font-semibold text-cyber-text mb-2">Something went wrong</h2>
          <p className="text-sm text-cyber-muted max-w-md mb-6">
            An unexpected error occurred while rendering this section. Try refreshing, or contact support if the issue persists.
          </p>
          {this.state.error && (
            <details className="mb-6 max-w-lg text-left">
              <summary className="text-xs text-cyber-muted cursor-pointer hover:text-cyber-text">
                Error details
              </summary>
              <pre className="mt-2 p-3 rounded-lg bg-red-500/5 border border-red-500/20 text-xs text-red-400 overflow-auto max-h-32 font-mono">
                {this.state.error.message}
              </pre>
            </details>
          )}
          <button
            onClick={this.handleRetry}
            className="flex items-center gap-2 rounded-lg bg-cyber-accent px-5 py-2.5 text-sm font-medium text-white hover:bg-cyber-accent/90 transition-colors"
          >
            <RefreshCw size={16} />
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
