import { UserCredentials, login } from "@/lib/actions";
import { redirect } from "next/navigation";

export default function LoginPage() {
  async function handleLogin(formdata: FormData) {
    "use server";
    const userobj = Object.fromEntries(formdata);
    await login(userobj as UserCredentials);
    redirect("/");
  }
  return (
    <form
      className="flex flex-col gap-4 max-w-[300px] m-5"
      action={handleLogin}
    >
      <input type="email" name="email" placeholder="email" required />
      <input type="password" name="password" placeholder="password" required />
      <button type="submit">login</button>
    </form>
  );
}
