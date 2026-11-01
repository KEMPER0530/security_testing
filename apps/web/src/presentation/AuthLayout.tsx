import type { ReactNode } from "react";
import "./login.css";

export function AuthHeader() {
  return (
    <header className="login-header">
      <a className="login-brand" href="/" aria-label="Security Testing ホーム">
        <span aria-hidden="true">◈</span> SECURITY TESTING
      </a>
      <span className="login-header-caption">
        サイト管理者のための診断ワークスペース
      </span>
    </header>
  );
}

export function AuthStory({ children }: { children?: ReactNode }) {
  return (
    <section className="login-story" aria-labelledby="login-intro">
      <div className="login-story-copy">
        <div className="login-eyebrow">KNOW YOUR EXPOSURE</div>
        <h1 id="login-intro">
          安全を確かめる、
          <br />
          その一歩から。
        </h1>
        <p>
          サイトの状態を知り、
          <br />
          次に取り組む対策を、明確に。
        </p>
        {children}
      </div>
      <div className="login-illustration" aria-hidden="true">
        <div className="login-orbit orbit-one" />
        <div className="login-orbit orbit-two" />
        <svg viewBox="0 0 140 160" fill="none">
          <path
            d="M70 12 123 34v43c0 34-22 57-53 72C39 134 17 111 17 77V34Z"
            stroke="currentColor"
            strokeWidth="2"
          />
          <path
            d="m47 78 17 17 32-37"
            stroke="currentColor"
            strokeWidth="5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
        <span className="login-node node-one">公開サイトを診断</span>
        <span className="login-node node-two">問題の深刻度を確認</span>
        <span className="login-node node-three">対策へつなげる</span>
      </div>
      <div className="login-story-foot">
        <span aria-hidden="true">01 — 02 — 03</span>
        <span>確認する。見つける。対策する。</span>
      </div>
    </section>
  );
}

export function AuthFooter() {
  return (
    <footer className="login-footer">
      <span>SECURITY TESTING</span>
      <span>観測した事実から、対策へ。</span>
    </footer>
  );
}
