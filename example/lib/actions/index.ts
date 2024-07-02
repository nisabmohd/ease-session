"use server";

import { User, createSession } from "@ease-session/auth";
import { EXPIRY } from "../util";

export type UserCredentials = User & { password: string };

export async function login(user: UserCredentials) {
  const { password, email } = user;
  if (password == "123")
    await createSession({ email }, { expiresAfter: EXPIRY });
}
