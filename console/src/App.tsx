import { useEffect, useState } from "react";

import { ApiError, signOut, whoAmI } from "./api";
import { Account } from "./views/Account";
import { AccessKeys } from "./views/AccessKeys";
import { Policies } from "./views/Policies";
import { SignIn } from "./views/SignIn";

type Tab = "account" | "keys" | "policies";

interface Identity {
  accountId: string;
  principalArn: string;
}

export function App() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [checking, setChecking] = useState(true);
  const [tab, setTab] = useState<Tab>("account");

  // A reload lands here with a cookie the browser kept and a CSRF token this page never saw,
  // because the token is held in memory only. Reads work; the first mutation will 401 and bounce
  // to sign-in. That is the honest consequence of not persisting the token, and the alternative
  // — storing it — would hand it to an XSS alongside nothing else of value.
  useEffect(() => {
    whoAmI()
      .then(setIdentity)
      .catch(() => setIdentity(null))
      .finally(() => setChecking(false));
  }, []);

  // Any 401 anywhere means the session is gone. Caught globally rather than per view, so no
  // screen has to remember to handle it and none can forget.
  useEffect(() => {
    function onRejection(e: PromiseRejectionEvent) {
      if (e.reason instanceof ApiError && e.reason.isUnauthenticated) setIdentity(null);
    }
    window.addEventListener("unhandledrejection", onRejection);
    return () => window.removeEventListener("unhandledrejection", onRejection);
  }, []);

  if (checking) return null;

  if (!identity) {
    return (
      <SignIn
        onSignedIn={(s) => setIdentity({ accountId: s.accountId, principalArn: s.principalArn })}
      />
    );
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          dariyanWS <span>console</span>
        </div>
        <div className="spacer" />
        <div className="whoami">
          <div className="mono">{identity.accountId}</div>
          <div>hind-1</div>
        </div>
        <button
          className="ghost"
          onClick={async () => {
            try {
              await signOut();
            } finally {
              setIdentity(null);
            }
          }}
        >
          Sign out
        </button>
      </header>

      <nav className="tabs">
        {(
          [
            ["account", "Account"],
            ["keys", "Access keys"],
            ["policies", "Policies"],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            aria-current={tab === id ? "page" : undefined}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === "account" && <Account principalArn={identity.principalArn} />}
      {tab === "keys" && <AccessKeys />}
      {tab === "policies" && (
        <Policies accountId={identity.accountId} principalArn={identity.principalArn} />
      )}
    </div>
  );
}
