import { useCallback, useEffect, useState } from "react";

import {
  createCacheCluster,
  deleteCacheCluster,
  listCacheClusters,
  type CacheCluster,
} from "../api";
import { Copyable } from "../components/Copyable";
import { Empty, ErrorNotice } from "../components/Notice";
import { ResourceState } from "../gen/dariya/common/v1/common_pb";
import { CacheNodeStatus } from "../gen/dariya/nache/v1/nache_pb";

// How often to re-read while anything is in flight. The reconciler's own period is 2s, so faster
// than that shows nothing new; much slower and CREATING → ACTIVE looks like it stalled.
const POLL_MS = 2000;

/** Exhaustive, no default: a state added to the proto is a compile error here, not a blank cell. */
function stateLabel(s: ResourceState): string {
  switch (s) {
    case ResourceState.UNSPECIFIED:
      return "unknown";
    case ResourceState.CREATING:
      return "creating";
    case ResourceState.ACTIVE:
      return "active";
    case ResourceState.UPDATING:
      return "updating";
    case ResourceState.DELETING:
      return "deleting";
    case ResourceState.FAILED:
      return "failed";
  }
}

function nodeLabel(s: CacheNodeStatus): string {
  switch (s) {
    case CacheNodeStatus.UNSPECIFIED:
      return "unknown";
    case CacheNodeStatus.CREATING:
      return "starting";
    case CacheNodeStatus.AVAILABLE:
      return "available";
    case CacheNodeStatus.IMPAIRED:
      return "impaired — being replaced";
  }
}

function inFlight(c: CacheCluster): boolean {
  if (c.state === ResourceState.CREATING || c.state === ResourceState.DELETING) return true;
  // An ACTIVE cluster whose node is being replaced is also worth watching.
  return c.nodes.some((n) => n.status !== CacheNodeStatus.AVAILABLE);
}

export function Caches({ accountId }: { accountId: string }) {
  const [clusters, setClusters] = useState<CacheCluster[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setClusters(await listCacheClusters());
    } catch (err) {
      setError(err);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Poll only while something is changing. A console left open on a converged list costs nothing.
  const polling = clusters?.some(inFlight) ?? false;
  useEffect(() => {
    if (!polling) return;
    const t = setInterval(() => void reload(), POLL_MS);
    return () => clearInterval(t);
  }, [polling, reload]);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      await createCacheCluster(name.trim());
      setName("");
      await reload();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function remove(n: string) {
    setError(null);
    try {
      await deleteCacheCluster(n);
      await reload();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <ErrorNotice error={error} />

      <div className="card">
        <h2>Cache clusters</h2>
        <p className="hint">
          A cluster is a dariyanache engine on its own machine, reachable only from this account's
          network at its endpoint. Creating one returns at once; the region makes it real, and
          replaces its node if it dies. A replaced node starts empty.
        </p>

        {clusters === null && !error && <Empty>Loading…</Empty>}
        {clusters?.length === 0 && <Empty>No cache clusters yet.</Empty>}

        {clusters && clusters.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>State</th>
                <th>Endpoint</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {clusters.map((c) => (
                <tr key={c.arn}>
                  <td>
                    <div>{c.name}</div>
                    {c.nodes.map((n) => (
                      <div key={n.nodeId} style={{ color: "var(--text-dim)", fontSize: 12 }}>
                        node {nodeLabel(n.status)}
                      </div>
                    ))}
                  </td>
                  <td>{stateLabel(c.state)}</td>
                  <td className="mono" style={{ fontSize: 13, wordBreak: "break-all" }}>
                    {c.endpoint}
                  </td>
                  <td className="actions">
                    <div className="row" style={{ justifyContent: "flex-end" }}>
                      <Copyable value={c.endpoint} />
                      <button
                        className="danger"
                        disabled={c.state === ResourceState.DELETING}
                        onClick={() => remove(c.name)}
                      >
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
        <h2>New cache cluster</h2>
        <p className="hint">
          Its endpoint will be <code>{name.trim() || "name"}.{accountId}.nache.dariya.internal:6379</code>{" "}
          — known before the node exists, and unchanged when it is replaced.
        </p>
        <div className="field">
          <label htmlFor="cname">Name — lowercase letters, digits and hyphens, up to 40</label>
          <input id="cname" value={name} onChange={(e) => setName(e.target.value)} placeholder="sessions" />
        </div>
        <button className="primary" onClick={create} disabled={busy || name.trim() === ""}>
          {busy ? "Creating…" : "Create cache cluster"}
        </button>
      </div>
    </>
  );
}
