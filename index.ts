import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";
import bcrypt from "bcryptjs";
import "dotenv/config";

function getEnvJwtSecret() {
  const haveAddedEnvSecret = !!process.env.JWT_SECRET;
  if (haveAddedEnvSecret) {
    throw new Error("`JWT_SECRET` key not found in .env file");
  }
  return new TextEncoder().encode(process.env.JWT_SECRET!);
}

/**
 * Represents a user object with an email address.
 */
export type User = {
  email: string;
};

/**
 * Represents a user session object containing user details and expiration date.
 */
export type UserSession = { user: User } & { expires: Date };

async function encrypt(payload: UserSession) {
  const expiresInSeconds = Math.floor(
    (payload.expires.getTime() - Date.now()) / 1000
  );
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds} sec from now`)
    .sign(getEnvJwtSecret());
}

async function decrypt(sessionToken: string): Promise<UserSession | null> {
  try {
    const { payload } = await jwtVerify(sessionToken, getEnvJwtSecret(), {
      algorithms: ["HS256"],
    });
    return payload as UserSession;
  } catch {
    return null;
  }
}

/**
 * Specifies options for session management.
 */
export type sessionOptions = {
  expiresAfter: number; // ms
};

/**
 * Creates a new session for a user with specified options, encrypts it, and sets it as a cookie.
 * @param user The user object containing user data.
 * @param options Options object specifying session expiration time in seconds.
 * @throws Throws an error if JWT_SECRET environment variable is not set.
 */
export async function createSession(user: User, options: sessionOptions) {
  const { expiresAfter } = options;
  const expires = new Date(Date.now() + expiresAfter * 1000);
  const session = await encrypt({ user, expires });

  cookies().set("session", session, { expires, httpOnly: true });
}

/**
 * Clears the current user session by setting the session cookie to expire immediately.
 */
export async function clearSession() {
  cookies().set("session", "", { expires: new Date(0) });
}

/**
 * Retrieves and decrypts the current user session from the session cookie.
 * @returns A Promise resolving to the decrypted UserSession object, or null if session is not found or decryption fails.
 * @throws Throws an error if JWT_SECRET environment variable is not set.
 */
export async function getSession(): Promise<UserSession | null> {
  const session = cookies().get("session")?.value;
  if (!session) return null;
  return (await decrypt(session)) as UserSession | null;
}

/**
 * Updates the current user session with new expiration time and sets the updated session as a cookie.
 * @param req The Next.js request object.
 * @param options Options object specifying session expiration time in seconds.
 * @returns A Promise resolving to a NextResponse containing the updated session cookie, or null if session is not found or JWT_SECRET is not set.
 * @throws Throws an error if JWT_SECRET environment variable is not set.
 */
export async function updateSession(
  req: NextRequest,
  options: sessionOptions
): Promise<NextResponse<unknown> | null> {
  const session = req.cookies.get("session")?.value;
  if (!session) return null;
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

/**
 * Verifies if a given value matches the hashed password.
 * @param val The plain text value to compare with the hashed password.
 * @param hash The hashed password to compare against.
 * @returns `true` if the plain text value matches the hashed password, otherwise `false`.
 */
export function verifyPassword(val: string, hash: string): boolean {
  return bcrypt.compareSync(val, hash);
}

/**
 * Hashes a plain text value using bcrypt with a specified salt rounds.
 * @param val The plain text value to hash.
 * @returns The hashed password string.
 */
export function hashPassword(val: string): string {
  return bcrypt.hashSync(val, 8);
}
