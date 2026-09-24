import { useEffect, useState } from "react";

import { getAccount, type Account as AccountModel } from "../api";
import { Copyable } from "../components/Copyable";
import { stateLabel } from "../state";
import { ErrorNotice } from "../components/Notice";

export function Account({ principalArn }: { principalArn: string }) {
  const [account, setAccount] = useState<AccountModel | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    getAccount().then(setAccount).catch(setError);
  }, []);

  return (
    <>
      <ErrorNotice error={error} />

      <div className="card">
        <h2>Account</h2>
        <p className="hint">
          Everything in this console acts on this account. There is no route that names another
          one.
        </p>

        {account ? (
          <table>
            <tbody>
              <tr>
                <td style={{ width: 160, color: "var(--text-dim)" }}>Account ID</td>
                <td className="mono">{account.accountId}</td>
                <td className="actions">
                  <Copyable value={account.accountId} />
                </td>
              </tr>
              <tr>
                <td style={{ color: "var(--text-dim)" }}>Name</td>
                <td>{account.name}</td>
                <td />
              </tr>
              <tr>
                <td style={{ color: "var(--text-dim)" }}>State</td>
                <td>{stateLabel(account.state)}</td>
                <td />
              </tr>
              <tr>
                <td style={{ color: "var(--text-dim)" }}>Signed in as</td>
                <td className="mono">{principalArn}</td>
                <td className="actions">
                  <Copyable value={principalArn} />
                </td>
              </tr>
              <tr>
                <td style={{ color: "var(--text-dim)" }}>Created</td>
                <td>{new Date(Number(account.createdAtUnixMs)).toLocaleString()}</td>
                <td />
              </tr>
            </tbody>
          </table>
        ) : (
          !error && <p className="empty">Loading…</p>
        )}
      </div>
    </>
  );
}
