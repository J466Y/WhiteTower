import { useEffect, useState } from "react";
import { api } from "./api/client";

type ServerStatus = { state: "loading" } | { state: "ok"; version: string } | { state: "error" };

export function App() {
  const [status, setStatus] = useState<ServerStatus>({ state: "loading" });

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

  return (
    <main>
      <h1>White Tower</h1>
      <p>Governance console, pre-alpha.</p>
      <p role="status">
        {status.state === "loading" && "Connecting to the server…"}
        {status.state === "ok" && `Server version ${status.version}`}
        {status.state === "error" && "The server is unreachable."}
      </p>
    </main>
  );
}
