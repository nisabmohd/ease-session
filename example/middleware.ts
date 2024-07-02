import { updateSession } from "@ease-session/auth";
import { NextRequest } from "next/server";
import { EXPIRY } from "./lib";

export async function middleware(req: NextRequest) {
  return await updateSession(req, { expiresAfter: EXPIRY });
}
