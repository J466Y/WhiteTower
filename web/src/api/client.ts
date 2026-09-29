import createClient from "openapi-fetch";
import type { paths } from "./schema.gen";

// Typed client of the public REST API. The types are generated from
// api/openapi/openapi.yaml with `task gen`; never edit schema.gen.ts by hand.
export const api = createClient<paths>({
  baseUrl: new URL("/api/v1", window.location.origin).toString(),
  // Resolve fetch at call time, so tests can stub it.
  fetch: (request) => globalThis.fetch(request),
});
