import { getSession, clearSession } from "@ease-session/auth";
import { redirect } from "next/navigation";

export default async function Home() {
  const session = await getSession();
  if (!session) redirect("/auth/login");
  return (
    <div>
      <pre>{JSON.stringify(session)}</pre>

      <form
        action={async function () {
          "use server";
          await clearSession();
        }}
      >
        <button type="submit">logout</button>
      </form>
    </div>
  );
}
