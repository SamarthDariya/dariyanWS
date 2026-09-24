import { useCallback, useEffect, useState } from "react";

import {
  attachPolicy,
  createPolicy,
  deletePolicy,
  detachPolicy,
  listPolicies,
  type Policy,
} from "../api";
import { Copyable } from "../components/Copyable";
import { Empty, ErrorNotice } from "../components/Notice";

const EXAMPLE = `{
  "statements": [
    {
      "sid": "invoke-everything",
      "effect": "EFFECT_ALLOW",
      "actions": ["func:Invoke"],
      "resources": ["*"]
    }
  ]
}`;

export function Policies({ accountId, principalArn }: { accountId: string; principalArn: string }) {
  const [policies, setPolicies] = useState<Policy[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [name, setName] = useState("");
  const [document, setDocument] = useState(EXAMPLE);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setPolicies(await listPolicies());
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
      // Parsed here so a typo is a message beside the textarea rather than a 400 from the
      // server describing a field path.
      let parsed: unknown;
      try {
        parsed = JSON.parse(document);
      } catch (err) {
        throw new Error(`the policy document is not valid JSON: ${String(err)}`);
      }

      await createPolicy(name.trim(), parsed);
      setName("");
      await reload();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function act(fn: () => Promise<void>) {
    setError(null);
    try {
      await fn();
      await reload();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <ErrorNotice error={error} />

      <div className="card">
        <h2>Policies</h2>
        <p className="hint">
          Deny wins, and nothing is permitted by default — a principal with no attached policy can
          do nothing at all.
        </p>

        {policies === null && !error && <Empty>Loading…</Empty>}
        {policies?.length === 0 && <Empty>No policies yet.</Empty>}

        {policies && policies.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Statements</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.policyArn}>
                  <td>
                    <div>{p.name}</div>
                    <div className="mono" style={{ color: "var(--text-dim)", fontSize: 12 }}>
                      {p.policyArn}
                    </div>
                  </td>
                  <td style={{ color: "var(--text-dim)", fontSize: 13 }}>
                    {p.document?.statements.map((s) => (
                      <div key={s.sid} className="mono">
                        {s.effect === 2 ? "deny" : "allow"} {s.actions.join(", ")} on{" "}
                        {s.resources.join(", ")}
                      </div>
                    ))}
                  </td>
                  <td className="actions">
                    <div className="row" style={{ justifyContent: "flex-end" }}>
                      <Copyable value={p.policyArn} />
                      <button
                        className="ghost"
                        onClick={() => act(() => attachPolicy(p.name, principalArn))}
                      >
                        Attach to me
                      </button>
                      <button
                        className="ghost"
                        onClick={() => act(() => detachPolicy(p.name, principalArn))}
                      >
                        Detach
                      </button>
                      <button className="danger" onClick={() => act(() => deletePolicy(p.name))}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>New policy</h2>
        <p className="hint">
          The name goes in the URL, which is what gets authorized — so it is decided before the
          document is read.
        </p>

        <div className="field">
          <label htmlFor="pname">Name</label>
          <input
            id="pname"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="invoke-all"
          />
        </div>

        <div className="field">
          <label htmlFor="pdoc">
            Document — resources are ARNs like{" "}
            <code>arn:dariya:func:hind-1:{accountId}:function/*</code>
          </label>
          <textarea id="pdoc" value={document} onChange={(e) => setDocument(e.target.value)} />
        </div>

        <button className="primary" onClick={create} disabled={busy || name.trim() === ""}>
          {busy ? "Creating…" : "Create policy"}
        </button>
      </div>
    </>
  );
}
