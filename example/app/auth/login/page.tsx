import { EXPIRY } from "@/lib";
import { createSession, User } from "@ease-session/auth";
import { redirect } from "next/navigation";

export default function LoginPage() {
  async function handleLogin(formdata: FormData) {
    "use server";
    const userobj = Object.fromEntries(formdata) as User;
    const { password, email } = userobj;
    if (password == "john123" && email == "johndoe@gmail.com") {
      await createSession(
        { email, username: "john" },
        { expiresAfter: EXPIRY }
      );
      redirect("/");
    }
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
