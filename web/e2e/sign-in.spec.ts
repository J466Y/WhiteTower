import { expect, type Page, test } from "@playwright/test";

// Signing in from a browser, through the realm of the development Keycloak
// (deploy/compose/dev/keycloak): the core sends the browser to Keycloak's form,
// then back to the console with a session. Its test users share a password, a
// public development fixture that their README documents.
const password = "whitetower";

// Every enabled user of the realm, and the roles that its groups map to.
const users = [
  { username: "steering", roles: ["steering"] },
  { username: "advisory", roles: ["advisory"] },
  { username: "owner", roles: ["owner"] },
  { username: "user", roles: ["user"] },
  { username: "operator", roles: ["operator"] },
  { username: "auditor", roles: ["auditor"] },
  { username: "admin", roles: ["admin"] },
  { username: "multirole", roles: ["operator", "owner"] },
];

// signIn opens the core's login, which sends the browser to Keycloak, and
// submits Keycloak's form.
async function signIn(page: Page, username: string) {
  await page.goto("/auth/login");
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
}

// backAtTheConsole waits until the browser is back at the console's root.
async function backAtTheConsole(page: Page, baseURL: string | undefined) {
  const root = new URL("/", baseURL ?? "https://127.0.0.1:8443").href;
  await page.waitForURL(root);
}

async function me(page: Page) {
  return page.request.get("/api/v1/me");
}

for (const { username, roles } of users) {
  test(`${username} signs in from a browser and holds the roles of their groups`, async ({
    page,
    baseURL,
  }) => {
    await signIn(page, username);
    await backAtTheConsole(page, baseURL);

    const response = await me(page);
    expect(response.status()).toBe(200);
    const principal = await response.json();
    expect(principal.kind).toBe("human");
    expect(principal.roles).toEqual(roles);
  });
}

test("inactive, a user that Keycloak disables, cannot sign in", async ({ page, baseURL }) => {
  const callbacks: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/auth/callback") {
      callbacks.push(request.url());
    }
  });

  await signIn(page, "inactive");

  await expect(page.getByText("Account is disabled")).toBeVisible();
  expect(new URL(page.url()).origin).not.toBe(new URL(baseURL ?? "https://127.0.0.1:8443").origin);
  // The callback is where the core creates or updates a principal: it never
  // sees this sign-in.
  expect(callbacks).toEqual([]);
  expect((await me(page)).status()).toBe(401);
});

test("signing out ends the session at the core and at Keycloak", async ({ page, baseURL }) => {
  await signIn(page, "owner");
  await backAtTheConsole(page, baseURL);

  // Keycloak keeps its own session: while it lasts, signing in again needs
  // no password.
  await page.goto("/auth/login");
  await backAtTheConsole(page, baseURL);
  expect((await me(page)).status()).toBe(200);

  // The core ends its session, then Keycloak asks to confirm the end of its
  // own, and sends the browser back to the console.
  await page.goto("/auth/logout");
  await page.locator("#kc-logout").click();
  await backAtTheConsole(page, baseURL);
  expect((await me(page)).status()).toBe(401);

  // Signing in again asks for the password.
  await page.goto("/auth/login");
  await expect(page.locator("#password")).toBeVisible();
});
