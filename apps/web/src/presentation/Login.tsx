import { useState, type FormEvent } from "react";
import type { PasswordAuth, SignInStep } from "../application/auth";
import "./login.css";
import { AuthHeader, AuthStory, AuthFooter } from "./AuthLayout";

type Stage = "signin" | "code" | "new-password" | "forgot" | "reset";
function message(error: unknown): string {
  const name = error instanceof Error ? error.name : "";
  if (["NotAuthorizedException", "UserNotFoundException"].includes(name))
    return "メールアドレスまたはパスワードが正しくありません。";
  if (name === "CodeMismatchException")
    return "確認コードが正しくありません。もう一度入力してください。";
  if (name === "ExpiredCodeException")
    return "確認コードの有効期限が切れました。最初からやり直してください。";
  if (["LimitExceededException", "TooManyRequestsException"].includes(name))
    return "試行回数が多くなっています。時間をおいてお試しください。";
  if (name === "InvalidPasswordException")
    return "パスワードの条件を確認してください。";
  if (
    error instanceof Error &&
    [
      "このアカウントには利用権限がありません。管理者に確認してください。",
      "追加の認証設定が必要です。管理者に確認してください。",
    ].includes(error.message)
  )
    return error.message;
  return "認証を完了できませんでした。接続を確認してもう一度お試しください。";
}

export function Login({ auth }: { auth: PasswordAuth }) {
  const [stage, setStage] = useState<Stage>("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [code, setCode] = useState("");
  const [channel, setChannel] = useState("");
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const newPassword = stage === "new-password" || stage === "reset";
  const needsPassword = stage === "signin" || newPassword;
  const needsCode = stage === "code" || stage === "reset";
  const titles: Record<Stage, string> = {
    signin: "ログイン",
    code: "確認コードを入力",
    "new-password": "新しいパスワードを設定",
    forgot: "パスワードを再設定",
    reset: "パスワードを再設定",
  };

  function back() {
    setStage("signin");
    setPassword("");
    setConfirmation("");
    setCode("");
    setVisible(false);
    setError("");
  }
  function next(step: SignInStep) {
    if (step.kind === "code") {
      setChannel(step.channel);
      setStage("code");
    }
    if (step.kind === "new-password") setStage("new-password");
    if (step.kind === "reset-password") {
      setStage("forgot");
      setNotice("パスワードの再設定が必要です。確認コードを送信してください。");
    }
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setError("");
    setNotice("");
    if (newPassword && password !== confirmation) {
      setError("パスワードが一致していません。");
      return;
    }
    setBusy(true);
    try {
      if (stage === "signin")
        next(await auth.signIn(username.trim(), password));
      else if (stage === "code") next(await auth.confirmSignIn(code.trim()));
      else if (stage === "new-password")
        next(await auth.confirmSignIn(password));
      else if (stage === "forgot") {
        await auth.resetPassword(username.trim());
        setStage("reset");
      } else {
        await auth.confirmResetPassword(username.trim(), code.trim(), password);
        back();
        setNotice(
          "パスワードを変更しました。新しいパスワードでログインしてください。",
        );
      }
    } catch (e) {
      setError(message(e));
    } finally {
      setPassword("");
      setConfirmation("");
      setBusy(false);
    }
  }

  return (
    <section className="login-page">
      <AuthHeader />
      <div className="login-layout">
        <AuthStory />
        <section className="login-form-area" aria-labelledby="login-title">
          <div className="login-card">
            <a className="login-home-link" href="/">
              ← トップへ戻る
            </a>
            <div className="login-eyebrow">YOUR WORKSPACE</div>
            <h2 id="login-title">{titles[stage]}</h2>
            <p className="login-description">
              {stage === "signin"
                ? "ご登録済みのアカウントでログインしてください。"
                : stage === "code"
                  ? `${channel}の確認コードを入力してください。`
                  : stage === "forgot"
                    ? "ご登録のアカウントへ確認コードを送信します。"
                    : stage === "reset"
                      ? "届いた確認コードと新しいパスワードを入力してください。"
                      : "アカウント用の新しいパスワードを設定してください。"}
            </p>
            <form onSubmit={(event) => void submit(event)} aria-busy={busy}>
              {(stage === "signin" || stage === "forgot") && (
                <div className="login-field">
                  <label htmlFor="login-username">
                    メールアドレス / ユーザー名
                  </label>
                  <input
                    id="login-username"
                    name="username"
                    autoComplete="username"
                    inputMode="email"
                    placeholder="メールアドレスを入力"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    disabled={busy}
                    required
                    maxLength={320}
                  />
                </div>
              )}
              {needsCode && (
                <div className="login-field">
                  <label htmlFor="login-code">確認コード</label>
                  <input
                    id="login-code"
                    name="code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    placeholder="6桁のコード"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    disabled={busy}
                    required
                  />
                </div>
              )}
              {needsPassword && (
                <div className="login-field">
                  <label htmlFor="login-password">
                    {newPassword ? "新しいパスワード" : "パスワード"}
                  </label>
                  <div className="login-password">
                    <input
                      id="login-password"
                      name="password"
                      type={visible ? "text" : "password"}
                      autoComplete={
                        newPassword ? "new-password" : "current-password"
                      }
                      placeholder={
                        newPassword
                          ? "新しいパスワードを入力"
                          : "パスワードを入力"
                      }
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={busy}
                      required
                      minLength={newPassword ? 8 : undefined}
                    />
                    <button
                      className="password-toggle"
                      type="button"
                      onClick={() => setVisible((v) => !v)}
                      aria-label={
                        visible ? "パスワードを非表示" : "パスワードを表示"
                      }
                      aria-pressed={visible}
                      disabled={busy}
                    >
                      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                        <path
                          d="M2 12s3-6 10-6 10 6 10 6-3 6-10 6S2 12 2 12Z"
                          stroke="currentColor"
                          strokeWidth="1.7"
                        />
                        <circle
                          cx="12"
                          cy="12"
                          r="3"
                          stroke="currentColor"
                          strokeWidth="1.7"
                        />
                        {visible && (
                          <path
                            d="m3 3 18 18"
                            stroke="currentColor"
                            strokeWidth="1.7"
                          />
                        )}
                      </svg>
                    </button>
                  </div>
                  {newPassword && (
                    <small>
                      8文字以上。英大文字・英小文字・数字・記号を含めてください。
                    </small>
                  )}
                </div>
              )}
              {newPassword && (
                <div className="login-field">
                  <label htmlFor="login-confirmation">
                    新しいパスワード（確認）
                  </label>
                  <input
                    id="login-confirmation"
                    name="confirmation"
                    type="password"
                    autoComplete="new-password"
                    value={confirmation}
                    onChange={(e) => setConfirmation(e.target.value)}
                    disabled={busy}
                    required
                    minLength={8}
                  />
                </div>
              )}
              {stage === "signin" && (
                <div className="login-help">
                  <button
                    type="button"
                    onClick={() => {
                      setStage("forgot");
                      setError("");
                      setNotice("");
                      setPassword("");
                    }}
                    disabled={busy}
                  >
                    パスワードを忘れた方
                  </button>
                </div>
              )}
              {error && (
                <div className="login-feedback is-error" role="alert">
                  {error}
                </div>
              )}
              {notice && (
                <div className="login-feedback" role="status">
                  {notice}
                </div>
              )}
              <button type="submit" className="login-submit" disabled={busy}>
                {busy ? (
                  <>
                    <span className="login-spinner" aria-hidden="true" />
                    確認しています…
                  </>
                ) : stage === "signin" ? (
                  <>
                    ログイン <span aria-hidden="true">→</span>
                  </>
                ) : stage === "forgot" ? (
                  "確認コードを送信"
                ) : stage === "code" ? (
                  "コードを確認"
                ) : (
                  "パスワードを設定"
                )}
              </button>
              {stage !== "signin" && (
                <button
                  className="login-back"
                  type="button"
                  onClick={back}
                  disabled={busy}
                >
                  ← ログインに戻る
                </button>
              )}
            </form>
            <div className="login-card-footer">
              <span aria-hidden="true">◈</span>
              <p>
                アカウントの利用には、
                <br className="login-mobile-break" />
                管理者による登録が必要です。
              </p>
            </div>
          </div>
        </section>
      </div>
      <AuthFooter />
    </section>
  );
}
