// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
vi.mock("aws-amplify", () => ({ Amplify: { configure: vi.fn() } }));
vi.mock("aws-amplify/auth/cognito", () => ({
  cognitoUserPoolsTokenProvider: { setKeyValueStorage: vi.fn() },
}));
vi.mock("aws-amplify/utils", () => ({ sessionStorage: {} }));
vi.mock("aws-amplify/auth", () => ({
  signIn: vi.fn(),
  confirmSignIn: vi.fn(),
  signOut: vi.fn(),
  fetchAuthSession: vi.fn(),
  resetPassword: vi.fn(),
  confirmResetPassword: vi.fn(),
}));
import * as sdk from "aws-amplify/auth";
import { CognitoIdentity } from "./cognito";
function session(
  group = "security-testing-users",
  token = "test-access-token",
) {
  return {
    tokens: {
      accessToken: {
        payload: {
          sub: "owner",
          exp: Date.now() / 1000 + 1800,
          "cognito:groups": [group],
        },
        toString: () => token,
      },
    },
  } as Awaited<ReturnType<typeof sdk.fetchAuthSession>>;
}
beforeEach(() => {
  vi.useFakeTimers();
  vi.mocked(sdk.fetchAuthSession).mockResolvedValue(session());
});
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.resetAllMocks();
});

it("CognitoのSRPログインを使い、権限を確認してセッションを通知する", async () => {
  vi.mocked(sdk.signIn).mockResolvedValue({
    isSignedIn: true,
    nextStep: { signInStep: "DONE" },
  });
  const auth = new CognitoIdentity(
    "https://cognito-idp.ap-northeast-1.amazonaws.com/pool",
    "client",
  );
  const loaded = vi.fn();
  auth.events.addUserLoaded(loaded);
  expect(await auth.signIn("owner", "dummy-password")).toEqual({
    kind: "done",
  });
  expect(sdk.signIn).toHaveBeenCalledWith({
    username: "owner",
    password: "dummy-password",
    options: { authFlowType: "USER_SRP_AUTH" },
  });
  expect(loaded).toHaveBeenCalledWith(
    expect.objectContaining({
      access_token: "test-access-token",
      profile: { sub: "owner" },
    }),
  );
});

it("別アプリのグループにしか所属しないアカウントを受け付けない", async () => {
  vi.mocked(sdk.fetchAuthSession).mockResolvedValue(
    session("other-application"),
  );
  const auth = new CognitoIdentity(
    "https://cognito-idp.ap-northeast-1.amazonaws.com/pool",
    "client",
  );
  await expect(auth.getUser()).rejects.toThrow("利用権限がありません");
  expect(sdk.signOut).toHaveBeenCalledOnce();
});

it("期限前にSDKで更新し、失敗時に期限切れを通知する", async () => {
  const auth = new CognitoIdentity(
    "https://cognito-idp.ap-northeast-1.amazonaws.com/pool",
    "client",
  );
  const expired = vi.fn();
  auth.events.addAccessTokenExpired(expired);
  await auth.getUser();
  vi.mocked(sdk.fetchAuthSession).mockRejectedValueOnce(
    new Error("refresh-failed"),
  );
  await vi.advanceTimersByTimeAsync(1740 * 1000);
  expect(sdk.fetchAuthSession).toHaveBeenLastCalledWith({ forceRefresh: true });
  expect(expired).toHaveBeenCalledOnce();
});
