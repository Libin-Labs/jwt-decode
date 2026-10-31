/** Registered JWT claims. Decoding does not validate their values or types. */
export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [claim: string]: unknown;
}

/** Common JOSE header parameters. Decoding does not enforce an algorithm. */
export interface JwtHeader {
  alg?: string;
  typ?: string;
  cty?: string;
  kid?: string;
  crit?: string[];
  [parameter: string]: unknown;
}

export interface DecodeOptions {
  /** Decode the first segment instead of the second. Default: false. */
  header?: boolean;
  /** Positive integer token-length limit in UTF-16 code units. Default: 1,048,576. */
  maxTokenLength?: number;
}

export type InvalidTokenCode =
  | 'INVALID_TOKEN'
  | 'TOKEN_TOO_LARGE'
  | 'INVALID_STRUCTURE'
  | 'INVALID_BASE64URL'
  | 'INVALID_UTF8'
  | 'INVALID_JSON'
  | 'INVALID_OBJECT';

/** Does not include token contents in its message. */
export class InvalidTokenError extends Error {
  readonly code: InvalidTokenCode;
  readonly segment: 'header' | 'payload' | undefined;

  constructor(message: string, code: InvalidTokenCode, segment?: 'header' | 'payload') {
    super(message);
    this.name = 'InvalidTokenError';
    this.code = code;
    this.segment = segment;
  }
}

export const DEFAULT_MAX_TOKEN_LENGTH = 1_048_576;
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function decodeSegment(encoded: string, segment: 'header' | 'payload'): unknown {
  const invalidBase64 = (): never => {
    throw new InvalidTokenError(
      `Invalid ${segment}: expected canonical unpadded Base64URL.`,
      'INVALID_BASE64URL',
      segment,
    );
  };
  if (encoded.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    return invalidBase64();
  }
  const bytes = new Uint8Array(Math.floor((encoded.length * 6) / 8));
  let accumulator = 0;
  let bits = 0;
  let offset = 0;
  for (const character of encoded) {
    accumulator = (accumulator << 6) | alphabet.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset++] = (accumulator >> bits) & 255;
    }
    accumulator &= (1 << bits) - 1;
  }
  if (accumulator !== 0) return invalidBase64();

  let text: string;
  try {
    // Preserve a BOM so JSON.parse rejects it instead of silently stripping it.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    throw new InvalidTokenError(
      `Invalid ${segment}: bytes are not valid UTF-8.`,
      'INVALID_UTF8',
      segment,
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new InvalidTokenError(
      `Invalid ${segment}: contents are not valid JSON.`,
      'INVALID_JSON',
      segment,
    );
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new InvalidTokenError(
      `Invalid ${segment}: JSON must be an object.`,
      'INVALID_OBJECT',
      segment,
    );
  }
  return value;
}

export function jwtDecode<T = JwtHeader>(
  token: string,
  options: DecodeOptions & { header: true },
): T;
export function jwtDecode<T = JwtPayload>(
  token: string,
  options?: DecodeOptions & { header?: false },
): T;
export function jwtDecode<T = JwtHeader | JwtPayload>(token: string, options: DecodeOptions): T;
export function jwtDecode<T = JwtPayload>(token: string, options?: DecodeOptions): T {
  if (
    options !== undefined &&
    (options === null || typeof options !== 'object' || Array.isArray(options))
  ) {
    throw new TypeError('Decode options must be an object.');
  }
  if (options?.header !== undefined && typeof options.header !== 'boolean') {
    throw new TypeError('The header option must be a boolean.');
  }
  const limit =
    options?.maxTokenLength === undefined ? DEFAULT_MAX_TOKEN_LENGTH : options.maxTokenLength;
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError('maxTokenLength must be a positive safe integer.');
  }
  if (typeof token !== 'string') {
    throw new InvalidTokenError('Token must be a string.', 'INVALID_TOKEN');
  }
  if (token.length > limit) {
    throw new InvalidTokenError('Token exceeds maxTokenLength.', 'TOKEN_TOO_LARGE');
  }
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    throw new InvalidTokenError(
      'Token must contain three dot-separated segments with a nonempty header and payload.',
      'INVALID_STRUCTURE',
    );
  }
  const segment = options?.header === true ? 'header' : 'payload';
  return decodeSegment(parts[segment === 'header' ? 0 : 1]!, segment) as T;
}
