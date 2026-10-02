# Errors of the public API

The public API answers every error with [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem details, as `application/problem+json`:

```json
{
  "type": "https://github.com/J466Y/WhiteTower/blob/main/docs/reference/api-errors.md#not_found",
  "title": "Not found",
  "status": 404,
  "detail": "no operation of the API has this path",
  "instance": "urn:uuid:01a0f7d4-3ce0-7753-b1d4-150e0e4ee010",
  "code": "not_found"
}
```

- `code` is the stable error code, which `type` repeats in a link to this page. Clients, the console among them, rely on it; the console shows its own translated message for it.
- `title` is the same for every occurrence of the code; `detail` explains this one, in English. Neither ever carries internal details (threat model, T-10).
- `instance` is the request ID, which the response also returns in `X-Request-Id` and the server's logs record: quote it when you report a problem.
- `429` answers carry `Retry-After`, and `405` answers carry `Allow`.

## Codes

The codes are defined in `internal/api/rest/problem`; a test keeps this table in step with them.

| Code | Status | Meaning |
| --- | --- | --- |
| `bad_request` | 400 | The request is malformed: a body that is not JSON, or a parameter that is missing or malformed. |
| `invalid_cursor` | 400 | The page cursor is not one the server gave: pass back the cursor of the previous page as it came. |
| `unauthenticated` | 401 | The operation needs a session or an API token, or the request's credentials were not accepted. |
| `forbidden` | 403 | The caller's roles do not permit the operation. |
| `not_found` | 404 | No resource, or no operation of the API, has this path. |
| `method_not_allowed` | 405 | The path exists, but not with this method; `Allow` lists those it supports. |
| `precondition_failed` | 412 | The resource changed since the client read it: read it again, then retry with the new ETag. |
| `payload_too_large` | 413 | The request body is larger than the server accepts (1 MiB on the console listener). |
| `precondition_required` | 428 | An update must send `If-Match` with the ETag of the version it changes, so that nobody silently overwrites someone else's change (threat model, T-08). |
| `rate_limited` | 429 | The caller sent too many requests; `Retry-After` says when to try again. |
| `internal` | 500 | The server failed. The details are in its logs, under the request ID. |

## Conventions that go with them

- **Lists** take `limit`, 50 by default and 200 at most, and `cursor`, which the previous page returned. A list returns at most one page, so no request asks for unbounded work (threat model, T-72).
- **Updates** need `If-Match` with the resource's `ETag`, a strong tag of its version.
- **Rate limits** apply per principal or, before login, per client address. The defaults allow 50 requests per second on average and 100 at once; `api.rate_limit` and `api.rate_burst` change them ([configuration reference](configuration.md)).
