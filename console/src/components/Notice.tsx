import { ApiError } from "../api";

/** Errors carry their request id, which is the entire reason it is in the body and not only a
 *  header — it is what somebody pastes into a message asking what went wrong. */
export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;

  if (error instanceof ApiError) {
    return (
      <div className="error" role="alert">
        <span className="code">{error.code}</span> — {error.message}
        {error.details && (
          <span className="rid">
            {Object.entries(error.details).map(([k, v]) => `${k}: ${v}`).join(" · ")}
          </span>
        )}
        {error.requestId && <span className="rid">request {error.requestId}</span>}
      </div>
    );
  }

  return (
    <div className="error" role="alert">
      {String((error as Error)?.message ?? error)}
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="empty">{children}</p>;
}
