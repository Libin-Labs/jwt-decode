import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { DEFAULT_MAX_TOKEN_LENGTH, InvalidTokenError, jwtDecode } from '@lp-labs/jwt-decode';

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const token = (payload, header = { alg: 'HS256', typ: 'JWT' }, signature = 'opaque') =>
  `${encode(header)}.${encode(payload)}.${signature}`;
function rejects(value, code, options, segment) {
  assert.throws(
    () => jwtDecode(value, options),
    (error) => {
      assert.ok(error instanceof InvalidTokenError);
      assert.equal(error.name, 'InvalidTokenError');
      assert.equal(error.code, code);
      assert.equal(error.segment, segment);
      return true;
    },
  );
}

test('decodes registered and custom claims without mutating input', () => {
  const payload = { sub: '123', aud: ['app'], exp: 1, roles: ['admin'], nested: { ok: true } };
  assert.deepEqual(jwtDecode(token(payload)), payload);
});
test('decodes header separately', () => {
  const header = { alg: 'RS256', kid: 'key-1', crit: ['custom'], custom: 1 };
  assert.deepEqual(jwtDecode(token({}, header), { header: true }), header);
});
test('supports UTF-8 including non-Latin text, emoji and supplementary code points', () => {
  const payload = {
    name: '\u65e5\u672c\u8a9e \u0645\u0631\u062d\u0628\u0627 \ud83c\udf0d',
    accent: 'caf\u00e9',
  };
  assert.deepEqual(jwtDecode(token(payload)), payload);
});
test('round-trips many encoded byte lengths and nested JSON values', () => {
  for (let length = 0; length < 200; length++) {
    const payload = { value: 'x'.repeat(length), nested: [null, true, 0, { x: '\u2713' }] };
    assert.deepEqual(jwtDecode(token(payload)), payload);
  }
});
test('does not verify signatures, claims, algorithm or token authenticity', () => {
  assert.deepEqual(jwtDecode(token({ exp: -1, aud: 99 }, { alg: 'none' }, '')), {
    exp: -1,
    aud: 99,
  });
  assert.deepEqual(jwtDecode(token({}, {}, 'not even base64!')), {});
});
test('decodes only the requested segment', () => {
  assert.deepEqual(jwtDecode(`!.${encode({ ok: true })}.`), { ok: true });
  assert.deepEqual(jwtDecode(`${encode({ alg: 'none' })}.!.`, { header: true }), { alg: 'none' });
});
test('rejects non-string input', () => {
  for (const value of [null, undefined, 1, {}, [], new String('x.y.z')]) {
    rejects(value, 'INVALID_TOKEN');
  }
});
test('rejects incorrect compact structure including JWE, detached and prefixed tokens', () => {
  for (const value of ['', 'a', 'a.b', 'a.b.c.d', 'a.b.c.d.e', '.a.', 'a..']) {
    rejects(value, 'INVALID_STRUCTURE');
  }
  rejects(`Bearer ${token({})}`, 'INVALID_BASE64URL', { header: true }, 'header');
});
test('rejects padded, standard-base64, whitespace and malformed Base64URL', () => {
  for (const segment of ['a', '====', 'e30=', 'e30+', 'e30/', 'e 30', 'e30\n', '\u00e9']) {
    rejects(`e30.${segment}.`, 'INVALID_BASE64URL', undefined, 'payload');
  }
});
test('rejects noncanonical trailing bits', () => {
  rejects('e30.e31.', 'INVALID_BASE64URL', undefined, 'payload');
});
test('rejects invalid UTF-8 rather than inserting replacement characters', () => {
  for (const bytes of [
    [0xff],
    [0xc0, 0xaf],
    [0xe2, 0x82],
    [0xed, 0xa0, 0x80],
    [0xf4, 0x90, 0x80, 0x80],
  ]) {
    rejects(
      `e30.${Buffer.from(bytes).toString('base64url')}.`,
      'INVALID_UTF8',
      undefined,
      'payload',
    );
  }
});
test('rejects malformed JSON and UTF-8 BOM', () => {
  for (const text of ['{', '{"a":}', '\ufeff{}', '{} trailing']) {
    rejects(
      `e30.${Buffer.from(text).toString('base64url')}.`,
      'INVALID_JSON',
      undefined,
      'payload',
    );
  }
});
test('rejects JSON primitives, null and arrays for either segment', () => {
  for (const value of [null, true, false, 1, 'text', []]) {
    rejects(token(value), 'INVALID_OBJECT', undefined, 'payload');
    rejects(token({}, value), 'INVALID_OBJECT', { header: true }, 'header');
  }
});
test('enforces total token length including signature at exact boundary', () => {
  const value = token({});
  assert.deepEqual(jwtDecode(value, { maxTokenLength: value.length }), {});
  rejects(value, 'TOKEN_TOO_LARGE', { maxTokenLength: value.length - 1 });
  rejects(`e30.e30.${'x'.repeat(DEFAULT_MAX_TOKEN_LENGTH)}`, 'TOKEN_TOO_LARGE');
});
test('rejects invalid options with explicit programmer errors', () => {
  for (const options of [null, 1, 'x', [], () => {}]) {
    assert.throws(() => jwtDecode(token({}), options), TypeError);
  }
  for (const header of [null, 1, 'yes']) {
    assert.throws(() => jwtDecode(token({}), { header }), TypeError);
  }
  for (const maxTokenLength of [
    null,
    0,
    -1,
    NaN,
    Infinity,
    1.5,
    '100',
    Number.MAX_SAFE_INTEGER + 1,
  ]) {
    assert.throws(() => jwtDecode(token({}), { maxTokenLength }), RangeError);
  }
});
test('error messages do not expose token contents', () => {
  const secret = 'private-content';
  assert.throws(
    () => jwtDecode(secret),
    (error) => !error.message.includes(secret),
  );
});
test('dangerous property names are parsed as own JSON fields without prototype mutation', () => {
  const json = '{"__proto__":{"polluted":true},"constructor":{"x":1}}';
  const value = jwtDecode(`e30.${Buffer.from(json).toString('base64url')}.`);
  assert.equal(Object.prototype.polluted, undefined);
  assert.ok(Object.hasOwn(value, '__proto__'));
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
});
test('duplicate JSON keys follow JSON.parse behavior and outputs are independent objects', () => {
  const value = `e30.${Buffer.from('{"x":1,"x":2}').toString('base64url')}.`;
  assert.deepEqual(jwtDecode(value), { x: 2 });
  assert.notEqual(jwtDecode(value), jwtDecode(value));
});
test('CommonJS and ESM expose equivalent API and decoding behavior', () => {
  const cjs = createRequire(import.meta.url)('@lp-labs/jwt-decode');
  assert.deepEqual(Object.keys(cjs).sort(), [
    'DEFAULT_MAX_TOKEN_LENGTH',
    'InvalidTokenError',
    'jwtDecode',
  ]);
  assert.deepEqual(cjs.jwtDecode(token({ sub: 'abc' })), jwtDecode(token({ sub: 'abc' })));
});
test('decodes without Buffer, atob, window or document globals', () => {
  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `
    const encoded = ${JSON.stringify(token({ sub: 'portable' }))};
    for (const name of ['Buffer', 'atob', 'window', 'document']) {
      Object.defineProperty(globalThis, name, { get() { throw new Error('Unexpected global: ' + name); } });
    }
    const { jwtDecode } = await import('@lp-labs/jwt-decode');
    if (jwtDecode(encoded).sub !== 'portable') throw new Error('Incorrect result');
  `,
    ],
    { cwd: new URL('../', import.meta.url), stdio: 'pipe' },
  );
});
