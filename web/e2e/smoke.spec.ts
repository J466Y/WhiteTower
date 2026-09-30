import { expect, test } from "@playwright/test";

test("the console loads from the core and nothing leaves the deployment", async ({
  page,
  baseURL,
}) => {
  const origin = new URL(baseURL ?? "https://127.0.0.1:8443").origin;
  const external: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.protocol.startsWith("http") && url.origin !== origin) {
      external.push(request.url());
    }
  });
  const violations: string[] = [];
  page.on("console", (message) => {
    if (message.text().includes("Content Security Policy")) {
      violations.push(message.text());
    }
  });

  const response = await page.goto("/");
  expect(response?.headers()["content-security-policy"]).toContain("default-src 'self'");
  await expect(page).toHaveTitle("White Tower");
  await expect(page.getByRole("status")).toHaveText(/^Server version /);

  expect(external, "requests to other origins (NFR-14)").toEqual([]);
  expect(violations, "Content Security Policy violations").toEqual([]);
});
