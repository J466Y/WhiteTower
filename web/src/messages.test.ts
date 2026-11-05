import { describe, expect, it } from "vitest";
import { messagesFor } from "./messages";

describe("messagesFor", () => {
  it.each([
    [["es-ES", "en"], "Cerrar sesión"],
    [["fr-FR", "es"], "Cerrar sesión"],
    [["en-GB", "es"], "Sign out"],
    [["fr-FR"], "Sign out"],
    [[], "Sign out"],
  ])("speaks the first language of %j that the console speaks", (languages, signOut) => {
    expect(messagesFor(languages).signOut).toBe(signOut);
  });
});
