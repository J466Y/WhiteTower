import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type Call = { route: string; csrfToken: string | null };

// stubServer answers each request whose method and path name a route, and
// 404 to any other, and returns the requests it received.
function stubServer(routes: Record<string, () => Response>): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request =
        typeof input === "string"
          ? new Request(new URL(input, window.location.origin), init)
          : input;
      const route = `${request.method} ${new URL(request.url).pathname}`;
      calls.push({ route, csrfToken: request.headers.get("X-CSRF-Token") });
      return routes[route]?.() ?? json({}, 404);
    }),
  );
  return calls;
}

const version = () => json({ version: "1.2.3", commit: "abc", apiVersion: "v1" });
const signedIn = () =>
  json({
    id: "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59",
    kind: "human",
    displayName: "Olivia Owner",
    roles: ["owner"],
    permissions: ["identity.me.read"],
    csrfToken: "the-session-csrf-token",
  });

describe("App", () => {
  it("shows the server version", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ version: "1.2.3", commit: "abc", apiVersion: "v1" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    render(<App />);
    expect(await screen.findByText("Server version 1.2.3")).toBeTruthy();
  });

  it("reports an unreachable server", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("network error");
      }),
    );
    render(<App />);
    expect(await screen.findByText("The server is unreachable.")).toBeTruthy();
  });

  it("signs out with a POST that carries the session's CSRF token, then goes where the server says", async () => {
    const calls = stubServer({
      "GET /api/v1/version": version,
      "GET /api/v1/me": signedIn,
      "POST /auth/logout": () => json({ redirect_url: "https://idp.example/logout?client_id=c" }),
    });
    const navigate = vi.fn();
    render(<App navigate={navigate} />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("https://idp.example/logout?client_id=c"),
    );
    expect(calls).toContainEqual({
      route: "POST /auth/logout",
      csrfToken: "the-session-csrf-token",
    });
  });

  it("offers no sign-out to a browser that is not signed in", async () => {
    stubServer({
      "GET /api/v1/version": version,
      "GET /api/v1/me": () => json({ code: "unauthenticated", status: 401 }, 401),
    });
    render(<App />);
    expect(await screen.findByText("Server version 1.2.3")).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("says that signing out failed, and stays", async () => {
    stubServer({
      "GET /api/v1/version": version,
      "GET /api/v1/me": signedIn,
      "POST /auth/logout": () => new Response("forbidden", { status: 403 }),
    });
    const navigate = vi.fn();
    render(<App navigate={navigate} />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "Signing out failed. Try again.",
    );
    expect(navigate).not.toHaveBeenCalled();
  });

  it("offers to sign out in Spanish to a browser that prefers it", async () => {
    vi.spyOn(navigator, "languages", "get").mockReturnValue(["es-ES", "en"]);
    stubServer({ "GET /api/v1/version": version, "GET /api/v1/me": signedIn });
    render(<App />);
    expect(await screen.findByRole("button", { name: "Cerrar sesión" })).toBeTruthy();
  });
});
