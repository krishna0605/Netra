import { Component, type ReactNode } from "react";
import { Link } from "react-router-dom";

type Props = {
  children: ReactNode;
  resetKey: string;
};

type State = { failed: boolean };

export class RouteErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidUpdate(previous: Props) {
    if (this.state.failed && previous.resetKey !== this.props.resetKey) {
      this.setState({ failed: false });
    }
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main id="main-content" className="surface rounded-[1.5rem] p-6" role="alert">
        <p className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-accent">NETRA / Route recovery</p>
        <h1 className="mt-3 text-3xl font-normal text-strong">This page could not be opened.</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
          The console navigation is still available. Open another section, or retry this page after refreshing.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          <button className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black" type="button" onClick={() => window.location.reload()}>
            Retry page
          </button>
          <Link className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-semibold text-strong" to="/app">
            Start investigation
          </Link>
        </div>
      </main>
    );
  }
}
