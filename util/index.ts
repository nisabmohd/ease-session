import bcrypt from "bcryptjs";

export function verifyPassword(hash: string, val: string) {
  return bcrypt.compareSync(val, hash);
}

export function hashPassword(val: string) {
  return bcrypt.hashSync(val, 8);
}
