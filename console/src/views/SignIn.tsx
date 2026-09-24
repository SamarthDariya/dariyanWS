import { useState, type FormEvent } from "react";

import { signIn, type SignInResult } from "../api";
import { ErrorNotice } from "../components/Notice";

/** The one screen reachable without a session, and the one moment a secret is typed in.
 *
 *  After this the browser holds a cookie it cannot read and the secret is gone from memory as
 *  soon as this component unmounts — which is the entire argument for decision 12. */
export function SignIn({ onSignedIn }: { onSignedIn: (s: SignInResult) => void }) {
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await signIn(accessKeyId.trim(), secret.trim()));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="signin">
      <div className="card">
        <h1>dariyanWS</h1>
        <p className="hint">
          Sign in with an access key pair. <code>make dev-token</code> prints one.
        </p>

        <ErrorNotice error={error} />

        <form onSubmit={submit}>
          <div className="field">
            <label htmlFor="key">Access key ID</label>
            <input
              id="key"
              className="mono"
              autoComplete="username"
              placeholder="DARIYAKEY…"
              value={accessKeyId}
              onChange={(e) => setAccessKeyId(e.target.value)}
              required
            />
          </div>

          <div className="field">
            <label htmlFor="secret">Secret access key</label>
            <input
              id="secret"
              className="mono"
              type="password"
              autoComplete="current-password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              required
            />
          </div>

          <button className="primary" type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
