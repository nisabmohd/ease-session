import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

const haveAddedEnvSecret = !!process.env.JWT_SECRET;
const JWTSECRET = new TextEncoder().encode(process.env.JWT_SECRET!);

type User = {
  email: string;
};

type UserSession = { user: User } & { expires: Date };

async function encrypt(payload: UserSession) {
  const expiresInSeconds = Math.floor(
    (payload.expires.getTime() - Date.now()) / 1000
  );
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds} sec from now`)
    .sign(JWTSECRET);
}

async function decrypt(sessionToken: string): Promise<UserSession | null> {
  try {
    const { payload } = await jwtVerify(sessionToken, JWTSECRET, {
      algorithms: ["HS256"],
    });
    return payload as UserSession;
  } catch {
    return null;
  }
}

export type sessionOptions = {
  expiresAfter: number; // ms
};

export async function createSession(user: User, options: sessionOptions) {
  if (!haveAddedEnvSecret)
    throw new Error("`JWT_SECRET` key not found in env config");
  const userData = user;
  const { expiresAfter } = options;
  const expires = new Date(Date.now() + expiresAfter * 1000);
  const session = await encrypt({ user: userData, expires });

  cookies().set("session", session, { expires, httpOnly: true });
}

export async function clearSession() {
  cookies().set("session", "", { expires: new Date(0) });
}

export async function getSession() {
  const session = cookies().get("session")?.value;
  if (!session) return null;
  if (!haveAddedEnvSecret)
    throw new Error("`JWT_SECRET` key not found in env config");
  return (await decrypt(session)) as UserSession | null;
}

export async function updateSession(req: NextRequest, options: sessionOptions) {
  const session = req.cookies.get("session")?.value;
  if (!session) return null;
  if (!haveAddedEnvSecret)
    throw new Error("`JWT_SECRET` key not found in env config");
  const { user } = (await decrypt(session)) as UserSession;
  const expires = new Date(Date.now() + options.expiresAfter * 1000);
  const newSession = await encrypt({ user, expires });

  const res = NextResponse.next();
  res.cookies.set({
    name: "session",
    value: newSession,
    httpOnly: true,
    expires,
  });
  return res;
}
