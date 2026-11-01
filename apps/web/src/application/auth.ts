export interface AuthSession {
  access_token: string;
  expired?: boolean;
  profile: { sub: string };
}

export type SignInStep =
  | { kind: "done" }
  | { kind: "code"; channel: string }
  | { kind: "new-password" }
  | { kind: "reset-password" };

export interface PasswordAuth {
  signIn(username: string, password: string): Promise<SignInStep>;
  confirmSignIn(response: string): Promise<SignInStep>;
  resetPassword(username: string): Promise<void>;
  confirmResetPassword(
    username: string,
    code: string,
    newPassword: string,
  ): Promise<void>;
}

type Loaded = (session: AuthSession) => void;
type Ended = () => void;
export interface IdentityPort {
  password?: PasswordAuth;
  getUser(): Promise<AuthSession | null>;
  signinRedirect(): Promise<void>;
  signinRedirectCallback(): Promise<AuthSession | null>;
  signoutRedirect(): Promise<void>;
  events: {
    addUserLoaded(callback: Loaded): void;
    removeUserLoaded(callback: Loaded): void;
    addUserUnloaded(callback: Ended): void;
    removeUserUnloaded(callback: Ended): void;
    addAccessTokenExpired(callback: Ended): void;
    removeAccessTokenExpired(callback: Ended): void;
  };
}
