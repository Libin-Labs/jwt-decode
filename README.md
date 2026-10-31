# @lp-labs/jwt-decode

Decode JWT headers and payloads in JavaScript or TypeScript without runtime
dependencies. Includes ESM, CommonJS, TypeScript declarations, strict unpadded
Base64URL decoding, UTF-8 validation and actionable errors.

**Decoding is not verification.** Anyone can construct a token this library can
decode. It does not verify signatures, enforce an algorithm, validate claims,
check expiration or establish authenticity. Never use its output alone to grant
access, establish identity or make authorization decisions.

## Installation

```sh
npm install @lp-labs/jwt-decode
```

```sh
pnpm add @lp-labs/jwt-decode
# or
yarn add @lp-labs/jwt-decode
```

Node.js 18+ and modern browsers with `TextDecoder` are supported. React, browser
DOM globals, `Buffer`, `atob`, network access and a framework provider are not
required. Bundlers can consume the ESM build; CommonJS consumers receive their
own build and declarations. The examples below use an unsigned sample token
for illustration, not a credential.

## Quick start

```js
import { jwtDecode } from '@lp-labs/jwt-decode';

const token = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.';
const payload = jwtDecode(token);
const header = jwtDecode(token, { header: true });

console.log(payload.sub); // "123"
console.log(header.alg); // "none" -- not a verified algorithm!
```

CommonJS:

```js
const { jwtDecode } = require('@lp-labs/jwt-decode');

const payload = jwtDecode('eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.');
console.log(payload.sub);
```

Do not pass an HTTP `Authorization` header such as `"Bearer <token>"`. Remove
the scheme in your application's header-processing code first. The decoder
does not trim whitespace, repair encodings or normalize input.

## API

### `jwtDecode<T>(token, options?)`

Synchronously decodes one segment of a three-segment compact token into a JSON
object. Returns a newly parsed object on each call.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `token` | `string` | required | Raw token in `header.payload.signature` form |
| `options.header` | `boolean` | `false` | Decode header instead of payload |
| `options.maxTokenLength` | `number` | `1_048_576` | Positive safe-integer limit on the entire token's UTF-16 length, including signature |

`DecodeOptions` is the exported options type. Supplying an invalid options
object or non-boolean `header` throws `TypeError`. An invalid `maxTokenLength`
throws `RangeError`; these are programmer errors rather than token errors.
Options are checked before token decoding.

```ts
import {
  jwtDecode,
  DEFAULT_MAX_TOKEN_LENGTH,
  type DecodeOptions,
  type JwtHeader,
  type JwtPayload,
} from '@lp-labs/jwt-decode';

const token = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.';
const payload: JwtPayload = jwtDecode(token);
const header: JwtHeader = jwtDecode(token, { header: true });
const options: DecodeOptions = { maxTokenLength: 16_384 };
const bounded = jwtDecode(token, options);

console.log(payload.sub, header.alg, bounded, DEFAULT_MAX_TOKEN_LENGTH);
```

Overload defaults:

- No options, or `header: false`: `JwtPayload`.
- Literal `header: true`: `JwtHeader`.
- A dynamically typed `DecodeOptions` value: `JwtHeader | JwtPayload`.
- Explicit `<T>`: the requested application type, without runtime schema validation.

### Custom application data

Generics are a TypeScript convenience, **not proof** that claims match your type.
Validate untrusted values before narrowing them:

```ts
import { jwtDecode } from '@lp-labs/jwt-decode';

interface AppClaims {
  sub: string;
  roles: string[];
}

export function readClaims(token: string): AppClaims {
  const decoded = jwtDecode<Record<string, unknown>>(token);
  if (
    typeof decoded.sub !== 'string' ||
    !Array.isArray(decoded.roles) ||
    !decoded.roles.every((role: unknown) => typeof role === 'string')
  ) {
    throw new TypeError('Token does not contain the expected application claims.');
  }
  return { sub: decoded.sub, roles: decoded.roles };
}
```

This checks the shape of the decoded data only. It still does not authenticate it.
If another trusted layer has already validated the schema, callers can use
`jwtDecode<AppClaims>(token)` directly, accepting responsibility for that assumption.

### Exported claim types

`JwtPayload` declares the common optional claims:

| Property | Declared type |
| --- | --- |
| `iss`, `sub`, `jti` | `string` |
| `aud` | `string \| string[]` |
| `exp`, `nbf`, `iat` | `number` |
| Other claim names | `unknown` |

JWT time claims conventionally use seconds since the Unix epoch, not JavaScript
milliseconds. Their declared types are not checked by the decoder.

`JwtHeader` declares optional `alg`, `typ`, `cty`, `kid` string fields and an
optional `crit: string[]`, plus other parameters as `unknown`.
Header parameters such as `crit` and `b64` are not interpreted or enforced.

### `DEFAULT_MAX_TOKEN_LENGTH`

Exported numeric constant: **1,048,576**. Override per call to fit your
application's input constraints. The limit prevents unbounded token processing
by default; it is not a general resource sandbox or JSON nesting limit.

## Errors

Malformed input throws `InvalidTokenError`, an exported `Error` subclass with:

- `name`: `"InvalidTokenError"`.
- `code`: an exported `InvalidTokenCode` string union.
- `segment`: `"header"`, `"payload"` or `undefined` for token-level failures.
- `message`: a description that does not contain the token or decoded data.

| Code | Meaning |
| --- | --- |
| `INVALID_TOKEN` | Runtime argument is not a primitive string |
| `TOKEN_TOO_LARGE` | Entire token exceeds the configured length |
| `INVALID_STRUCTURE` | Not exactly three segments, or empty header/payload |
| `INVALID_BASE64URL` | Selected segment has invalid characters, padding, length or nonzero unused bits |
| `INVALID_UTF8` | Selected segment contains malformed UTF-8 bytes |
| `INVALID_JSON` | Selected segment is not parseable JSON |
| `INVALID_OBJECT` | Selected segment is valid JSON but not a non-null, non-array object |

```ts
import { InvalidTokenError, jwtDecode } from '@lp-labs/jwt-decode';

export function inspectToken(token: string) {
  try {
    return jwtDecode<Record<string, unknown>>(token);
  } catch (error) {
    if (error instanceof InvalidTokenError) {
      // Report only error metadata; avoid logging credentials or decoded claims.
      console.warn('Cannot decode token', error.code, error.segment);
    }
    throw error;
  }
}
```

The public constructor is
`new InvalidTokenError(message, code, segment?)`. Library-generated messages avoid
token contents; messages you supply yourself are your responsibility.
Unexpected platform failures propagate instead of being replaced with an empty
object or a success-shaped fallback.

## Encoding and structure rules

The selected segment must use the JWT alphabet `A-Z a-z 0-9 - _`, without `=`
padding. Standard Base64 `+` and `/`, whitespace and noncanonical trailing bits
are rejected. UTF-8 decoding is fatal rather than replacing invalid bytes.
A leading UTF-8 BOM is not stripped and is rejected as invalid JSON.

Header and payload must be nonempty and the compact token must have exactly
three segments. An empty signature is allowed for inspecting unsecured tokens.
Only the **selected** segment is decoded: reading a payload does not parse the
header, and reading a header does not parse the payload. The signature is opaque
and unchecked; even an invalid signature string does not prevent decoding.
Successful decoding is therefore not a statement that the whole token is valid.

Parsing follows native `JSON.parse` semantics, including last-value-wins for
duplicate object keys and JavaScript number precision. Arbitrary claim keys,
including `__proto__`, remain ordinary parsed own properties; do not merge
untrusted decoded values into configuration or security-sensitive objects.

## Integration and customization

- **React/Vue/other frameworks:** call the pure function from application code;
  no hooks, provider, CSS or framework dependency is needed.
- **Server applications:** decode for inspection only; use a trusted JOSE/JWT
  verifier to check signatures, issuer, audience, algorithms and time claims.
- **Request handling:** enforce your own header/body limits before decoding.
  Supply a lower `maxTokenLength` when tokens come from untrusted input.
- **UI:** treat decoded strings as untrusted text; never inject claim contents
  directly as HTML or use embedded URLs without a URL policy.
- **Storage:** the library neither reads nor writes cookies, localStorage or
  sessionStorage. It does not choose a token storage strategy.

## Performance and compatibility

Selected-segment decoding is linear in its encoded length and allocates an
intermediate byte array, decoded string and parsed object. Full token structure
processing is linear in token length. There is no cache, state or network I/O.
No browser throughput or rendering guarantee is claimed.

Named exports are provided; there is no default export. This is an independent
implementation, not a wrapper or drop-in replacement for the existing
`jwt-decode` package. Stricter structure, encoding and object checks may reject
inputs tolerated by other decoders. No source was fetched from that package
during implementation; this is not an exhaustive similarity or legal audit.

## Scope and limitations

- No cryptographic verification, signing, key discovery or JWKS fetching.
- No claim enforcement, expiration helpers or trust decisions.
- No JWE decryption, five-segment tokens, detached payloads or unencoded payloads.
- No automatic Bearer-prefix removal or permissive Base64 repair.
- No runtime validation of generic claim schemas.
- Native JSON semantics apply; no duplicate-key detection or big-integer preservation.
- Requires a standards-compatible global `TextDecoder` at decoding time.

## License

[MIT](./LICENSE).

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
