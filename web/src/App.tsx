import { useEffect, useState } from "react";
import { api } from "./api/client";
import { messagesFor } from "./messages";
import { signOut } from "./signOut";

type ServerStatus = { state: "loading" } | { state: "ok"; version: string } | { state: "error" };

type AppProps = {
  // navigate sends the browser to url once signed out; tests replace it.
  navigate?: (url: string) => void;
};

export function App({ navigate = (url) => window.location.assign(url) }: AppProps) {
  const [status, setStatus] = useState<ServerStatus>({ state: "loading" });
  // The CSRF token of the browser's session, which /me gives only to a
  // signed-in browser: the console offers to sign out only then.
  const [csrfToken, setCSRFToken] = useState<string>();
  const [signOutFailed, setSignOutFailed] = useState(false);
  const t = messagesFor(navigator.languages);

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/version")
      .then(({ data }) => {
        if (!cancelled) {
          setStatus(data ? { state: "ok", version: data.version } : { state: "error" });
        }
      })
      .catch(() => {
        if (!cancelled) {
          setStatus({ state: "error" });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/me")
      .then(({ data }) => {
        if (!cancelled && data?.csrfToken) {
          setCSRFToken(data.csrfToken);
        }
      })
      // An unreachable server, which the status says.
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const onSignOut = (token: string) => {
    setSignOutFailed(false);
    signOut(token)
      .then(navigate)
      .catch(() => setSignOutFailed(true));
  };

  return (
    <main>
      <h1>White Tower</h1>
      <p>Governance console, pre-alpha.</p>
      <p role="status">
        {status.state === "loading" && "Connecting to the server…"}
        {status.state === "ok" && `Server version ${status.version}`}
        {status.state === "error" && "The server is unreachable."}
      </p>
      {csrfToken && (
        <button type="button" onClick={() => onSignOut(csrfToken)}>
          {t.signOut}
        </button>
      )}
      {signOutFailed && <p role="alert">{t.signOutFailed}</p>}
    </main>
  );
}
