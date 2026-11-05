// signOut ends the session at the core with a POST that carries the session's
// CSRF token, which the core asks of every sign-out so that another site
// cannot sign a person out (ADR-0009). It returns where the browser goes next:
// the identity provider's end session page, or the console's root. fetch
// cannot follow the core to the identity provider's origin, so the core
// answers the address, and the caller navigates.
export async function signOut(csrfToken: string): Promise<string> {
  const response = await fetch("/auth/logout", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
  });
  if (!response.ok) {
    throw new Error(`signing out: the server answered ${response.status}`);
  }
  const answer: { redirect_url?: unknown } = await response.json();
  if (typeof answer.redirect_url !== "string" || !isPage(answer.redirect_url)) {
    throw new Error("signing out: the server named no page to go to");
  }
  return answer.redirect_url;
}

// isPage reports whether url is a page that the console may send the browser
// to: a path of its own origin, or an https or http URL. The console navigates
// from its own origin, so a javascript: or data: URL, which a broken or
// hostile discovery document could name, would run in it.
function isPage(url: string): boolean {
  if (url.startsWith("/")) {
    return !url.startsWith("//") && !url.startsWith("/\\");
  }
  try {
    const { protocol } = new URL(url);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}
