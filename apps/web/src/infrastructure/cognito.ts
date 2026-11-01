import type {
  AuthSession,
  IdentityPort,
  PasswordAuth,
  SignInStep,
} from "../application/auth";

type Sdk = typeof import("aws-amplify/auth");
type Output = Awaited<ReturnType<Sdk["signIn"]>>;

export class CognitoIdentity implements IdentityPort, PasswordAuth {
  readonly password = this;
  private loaded = new Set<(user: AuthSession) => void>();
  private unloaded = new Set<() => void>();
  private expired = new Set<() => void>();
  private timer?: ReturnType<typeof setTimeout>;
  private initialization?: Promise<Sdk>;
  readonly events = {
    addUserLoaded: (fn: (user: AuthSession) => void) => {
      this.loaded.add(fn);
    },
    removeUserLoaded: (fn: (user: AuthSession) => void) => {
      this.loaded.delete(fn);
    },
    addUserUnloaded: (fn: () => void) => {
      this.unloaded.add(fn);
    },
    removeUserUnloaded: (fn: () => void) => {
      this.unloaded.delete(fn);
    },
    addAccessTokenExpired: (fn: () => void) => {
      this.expired.add(fn);
    },
    removeAccessTokenExpired: (fn: () => void) => {
      this.expired.delete(fn);
    },
  };

  constructor(
    private issuer: string,
    private clientId: string,
  ) {}

  private sdk(): Promise<Sdk> {
    this.initialization ??= (async () => {
      const [
        { Amplify },
        auth,
        { cognitoUserPoolsTokenProvider },
        { sessionStorage },
      ] = await Promise.all([
        import("aws-amplify"),
        import("aws-amplify/auth"),
        import("aws-amplify/auth/cognito"),
        import("aws-amplify/utils"),
      ]);
      const userPoolId = this.issuer.split("/").at(-1)!;
      Amplify.configure({
        Auth: { Cognito: { userPoolId, userPoolClientId: this.clientId } },
      });
      cognitoUserPoolsTokenProvider.setKeyValueStorage(sessionStorage);
      return auth;
    })();
    return this.initialization;
  }

  async getUser(forceRefresh = false): Promise<AuthSession | null> {
    const auth = await this.sdk();
    const { tokens } = await auth.fetchAuthSession({ forceRefresh });
    if (!tokens?.accessToken) return null;
    const claims = tokens.accessToken.payload;
    const groups = claims["cognito:groups"];
    if (!Array.isArray(groups) || !groups.includes("security-testing-users")) {
      await auth.signOut();
      throw new Error(
        "このアカウントには利用権限がありません。管理者に確認してください。",
      );
    }
    if (typeof claims.sub !== "string" || typeof claims.exp !== "number") {
      await auth.signOut();
      throw new Error(
        "ログイン状態を確認できません。もう一度ログインしてください。",
      );
    }
    if (claims.exp <= Date.now() / 1000) return null;
    const user: AuthSession = {
      access_token: tokens.accessToken.toString(),
      expired: false,
      profile: { sub: claims.sub },
    };
    clearTimeout(this.timer);
    this.timer = setTimeout(
      () => {
        void this.getUser(true)
          .then((next) => {
            if (next) this.loaded.forEach((fn) => fn(next));
            else this.expired.forEach((fn) => fn());
          })
          .catch(() => this.expired.forEach((fn) => fn()));
      },
      Math.max(1000, (claims.exp - Date.now() / 1000 - 60) * 1000),
    );
    return user;
  }

  private async next(result: Output): Promise<SignInStep> {
    const step = result.nextStep.signInStep;
    if (result.isSignedIn) {
      const user = await this.getUser();
      if (!user)
        throw new Error(
          "ログインを完了できませんでした。もう一度お試しください。",
        );
      this.loaded.forEach((fn) => fn(user));
      return { kind: "done" };
    }
    if (step === "CONFIRM_SIGN_IN_WITH_TOTP_CODE")
      return { kind: "code", channel: "認証アプリ" };
    if (step === "CONFIRM_SIGN_IN_WITH_SMS_CODE")
      return { kind: "code", channel: "SMS" };
    if (step === "CONFIRM_SIGN_IN_WITH_EMAIL_CODE")
      return { kind: "code", channel: "メール" };
    if (step === "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED")
      return { kind: "new-password" };
    if (step === "RESET_PASSWORD") return { kind: "reset-password" };
    throw new Error("追加の認証設定が必要です。管理者に確認してください。");
  }

  async signIn(username: string, password: string) {
    const auth = await this.sdk();
    return this.next(
      await auth.signIn({
        username,
        password,
        options: { authFlowType: "USER_SRP_AUTH" },
      }),
    );
  }
  async confirmSignIn(response: string) {
    return this.next(
      await (await this.sdk()).confirmSignIn({ challengeResponse: response }),
    );
  }
  async resetPassword(username: string) {
    await (await this.sdk()).resetPassword({ username });
  }
  async confirmResetPassword(
    username: string,
    code: string,
    newPassword: string,
  ) {
    await (
      await this.sdk()
    ).confirmResetPassword({ username, confirmationCode: code, newPassword });
  }
  async signoutRedirect() {
    clearTimeout(this.timer);
    await (await this.sdk()).signOut();
    this.unloaded.forEach((fn) => fn());
  }
  async signinRedirect(): Promise<void> {
    throw new Error("このサイトのログインフォームを利用してください。");
  }
  async signinRedirectCallback(): Promise<null> {
    return null;
  }
}
