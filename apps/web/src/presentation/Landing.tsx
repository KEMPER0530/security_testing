import { AuthHeader, AuthStory, AuthFooter } from "./AuthLayout";

export function Landing({
  onEnter,
  busy,
  error,
  buttonLabel = "ログイン",
}: {
  onEnter: () => Promise<void>;
  busy: boolean;
  error: string;
  buttonLabel?: string;
}) {
  return (
    <section className="login-page landing-page">
      <AuthHeader />
      <AuthStory>
        <div className="landing-entry">
          <button
            className="landing-login"
            onClick={() => void onEnter()}
            disabled={busy}
            aria-busy={busy}
          >
            {busy && <span className="login-spinner" aria-hidden="true" />}
            {buttonLabel}
            {buttonLabel === "ログイン" && <span aria-hidden="true">→</span>}
          </button>
          <p>ログインして診断ワークスペースへ</p>
          {error && (
            <p className="landing-error" role="alert">
              {error}
            </p>
          )}
        </div>
      </AuthStory>
      <AuthFooter />
    </section>
  );
}
