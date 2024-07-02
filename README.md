`ease-session` is a lightweight NextJs library for managing user sessions, authentication, and storage.

### usage:

`createSession`

```ts
// lib/auth.ts

"use server";
// ...

import { createSession, verifyPassword } from "@ease-session/auth";

export async function login(user: User) {
  const dbuser = findUserFromDb(user.email);
  if (!dbuser) throw new Error("user doesnt exist");
  const { password, ...rest } = user;
  const correct = verifyPassword(password, dbuser.password);
  if (!correct) throw new Error("invalid credentials");
  await createSession(rest);
}
```

```ts
// lib/auth.ts

"use server";
// ...

import { createSession, hashPassword } from "@ease-session/auth";

export async function signup(user: User) {
  const dbuser = findUserFromDb(user.email);
  if (dbuser) throw new Error("user already exist");
  const { password, ...rest } = user;
  await createUser({ ...rest, password: hashPassword(password) });
  await createSession(rest);
}
```

`clearSession`

```ts
// lib/auth.ts

"use server";
// ...

import { clearSession } from "@ease-session/auth";

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
  return <></>;
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

export async function middleware() {
  return await updateSession();
}
```
