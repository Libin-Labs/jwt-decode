import { jwtDecode, type JwtHeader, type JwtPayload } from '@lp-labs/jwt-decode';

const payload: JwtPayload = jwtDecode('a.b.c');
const header: JwtHeader = jwtDecode('a.b.c', { header: true });
const custom = jwtDecode<{ roles: string[] }>('a.b.c');
// @ts-expect-error declared custom property remains a string array.
const invalid: string = custom.roles;
void [payload, header, custom, invalid];
