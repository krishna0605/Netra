export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export type PasswordCheck = {
  key: "length" | "uppercase" | "lowercase" | "number" | "symbol";
  label: string;
  met: boolean;
};

export function passwordChecks(password: string): PasswordCheck[] {
  return [
    {
      key: "length",
      label: `${PASSWORD_MIN_LENGTH}–${PASSWORD_MAX_LENGTH} characters`,
      met: password.length >= PASSWORD_MIN_LENGTH && password.length <= PASSWORD_MAX_LENGTH,
    },
    { key: "uppercase", label: "One uppercase letter", met: /[A-Z]/.test(password) },
    { key: "lowercase", label: "One lowercase letter", met: /[a-z]/.test(password) },
    { key: "number", label: "One number", met: /\d/.test(password) },
    { key: "symbol", label: "One symbol", met: /[^A-Za-z0-9\s]/.test(password) },
  ];
}

export function validPassword(password: string) {
  return passwordChecks(password).every((check) => check.met);
}
