`ease-session` is a simple and efficient session management library for Next.js, designed to streamline authentication and session handling with minimal setup.

### usage:

`createSession`

```ts
// lib/auth.ts

"use server";

import { createSession, verifyPassword } from "@ease-session/auth";

// ...

export async function login(user: User) {
  const dbuser = await findUserFromDb(user.email);
  if (!dbuser) throw new Error("user doesnt exist");
  const { password, ...rest } = user;
  const correct = verifyPassword(password, dbuser.password);
  if (!correct) throw new Error("invalid credentials");
  await createSession(rest, {
    expiresAfter: 10,
  });
}
```

```ts
// lib/auth.ts

"use server";

import { createSession, hashPassword } from "@ease-session/auth";

// ...

export async function signup(user: User) {
  const dbuser = await findUserFromDb(user.email);
  if (dbuser) throw new Error("user already exist");
  const { password, ...rest } = user;
  await createDbUser({ ...rest, password: hashPassword(password) });
  await createSession(rest, {
    expiresAfter: 10,
  });
}
```

`clearSession`

```ts
// lib/auth.ts

"use server";

import { clearSession } from "@ease-session/auth";

// ...

export async function logout() {
  await clearSession();
}
```

`getSession`

```tsx
// page.tsx

import { getSession } from "@ease-session/auth";

export default async function Page() {
  const session = await getSession();
  if (!session) redirect("/login");
  return <div>{JSON.stringify(session)}<div/>;
}
```

```tsx
// api/route.tsx

import { getSession } from "@ease-session/auth";

export default async function GET() {
  const session = await getSession();
  if (!session) return "Unauthorized";
  return new Response("OK");
}
```

`updateSession`

```tsx
// middleware.ts

import { updateSession } from "@ease-session/auth";

export async function middleware(req) {
  return await updateSession(req, {
    expiresAfter: 10,
  });
}
```
