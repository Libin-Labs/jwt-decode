import {
  DEFAULT_MAX_TOKEN_LENGTH,
  InvalidTokenError,
  jwtDecode,
  type DecodeOptions,
  type InvalidTokenCode,
  type JwtHeader,
  type JwtPayload,
} from '@lp-labs/jwt-decode';

const payload: JwtPayload = jwtDecode('a.b.c');
const header: JwtHeader = jwtDecode('a.b.c', { header: true });
const user = jwtDecode<{ userId: string }>('a.b.c');
const options: DecodeOptions = { header: Math.random() > 0.5 };
const dynamic: JwtPayload | JwtHeader = jwtDecode('a.b.c', options);
const code: InvalidTokenCode = new InvalidTokenError('Invalid token', 'INVALID_TOKEN').code;
// @ts-expect-error header must be a boolean.
jwtDecode('a.b.c', { header: 'yes' });
// @ts-expect-error token must be a string.
jwtDecode(123);
// @ts-expect-error custom fields retain their declared types.
const invalid: number = user.userId;
void [payload, header, dynamic, code, invalid, DEFAULT_MAX_TOKEN_LENGTH];
