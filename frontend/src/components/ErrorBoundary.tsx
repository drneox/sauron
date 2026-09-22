import { Component, ReactNode, ErrorInfo } from 'react'
import { AlertTriangle } from 'lucide-react'

interface Props { children: ReactNode }
interface State { hasError: boolean; error: Error | null }

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('ReportView crash:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="max-w-2xl mx-auto mt-16 p-6 bg-red-50 border border-red-200 rounded-xl">
          <h2 className="text-red-700 font-semibold text-lg mb-2 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" /> Render Error
          </h2>
          <pre className="text-red-800 text-xs whitespace-pre-wrap break-all bg-white border border-red-100 p-4 rounded-lg font-mono">
            {this.state.error?.message}
            {'\n\n'}
            {this.state.error?.stack?.split('\n').slice(0, 8).join('\n')}
          </pre>
          <button
            className="mt-4 px-4 py-2 bg-white hover:bg-dark-900 border border-dark-700 text-dark-200 rounded-lg text-sm transition-colors duration-150"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Dismiss
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
