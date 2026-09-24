import { useCallback, useEffect, useState } from "react";

import { createAccessKey, deleteAccessKey, listAccessKeys, type AccessKey } from "../api";
import { Copyable } from "../components/Copyable";
import { Empty, ErrorNotice } from "../components/Notice";

export function AccessKeys() {
  const [keys, setKeys] = useState<AccessKey[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  // The secret exists in exactly one response and is never retrievable again, so it lives here
  // in component state until the page is left. Persisting it anywhere would quietly undo the
  // property the server works to maintain.
  const [freshSecret, setFreshSecret] = useState<{ id: string; secret: string } | null>(null);

  const reload = useCallback(async () => {
    try {
      setKeys(await listAccessKeys());
    } catch (err) {
      setError(err);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const key = await createAccessKey();
      setFreshSecret({ id: key.accessKeyId, secret: key.secretAccessKey });
      await reload();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      await deleteAccessKey(id);
      if (freshSecret?.id === id) setFreshSecret(null);
      await reload();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <ErrorNotice error={error} />

      {freshSecret && (
        <div className="secret">
          <h3>Copy this secret now</h3>
          <p>
            It is shown once. The server keeps only an encrypted copy and cannot show it to you
            again — if you lose it, delete the key and create another.
          </p>
          <code className="value">{freshSecret.secret}</code>
          <div className="row">
            <Copyable value={freshSecret.secret} />
            <button className="ghost" onClick={() => setFreshSecret(null)}>
              Done
            </button>
          </div>
        </div>
      )}

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 14 }}>
          <div>
            <h2 style={{ marginBottom: 2 }}>Access keys</h2>
            <p className="hint" style={{ margin: 0 }}>
              Long-lived credentials for signing API requests.
            </p>
          </div>
          <button className="primary" onClick={create} disabled={busy}>
            {busy ? "Creating…" : "Create access key"}
          </button>
        </div>

        {keys === null && !error && <Empty>Loading…</Empty>}
        {keys?.length === 0 && <Empty>No access keys. Create one to sign API requests.</Empty>}

        {keys && keys.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Access key ID</th>
                <th>Principal</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.accessKeyId}>
                  <td className="mono">{k.accessKeyId}</td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {k.principalArn}
                  </td>
                  <td style={{ color: "var(--text-dim)" }}>
                    {new Date(Number(k.createdAtUnixMs)).toLocaleDateString()}
                  </td>
                  <td className="actions">
                    <button className="danger" onClick={() => remove(k.accessKeyId)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
