// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { Login } from "./Login";
import type { PasswordAuth, SignInStep } from "../application/auth";

afterEach(cleanup);
function adapter() {
  return {
    signIn: vi.fn<PasswordAuth["signIn"]>().mockResolvedValue({ kind: "done" }),
    confirmSignIn: vi
      .fn<PasswordAuth["confirmSignIn"]>()
      .mockResolvedValue({ kind: "done" }),
    resetPassword: vi
      .fn<PasswordAuth["resetPassword"]>()
      .mockResolvedValue(undefined),
    confirmResetPassword: vi
      .fn<PasswordAuth["confirmResetPassword"]>()
      .mockResolvedValue(undefined),
  };
}
function enterCredentials() {
  fireEvent.change(screen.getByLabelText("メールアドレス / ユーザー名"), {
    target: { value: " owner@example.test " },
  });
  fireEvent.change(screen.getByLabelText("パスワード", { exact: true }), {
    target: { value: "ExamplePassword1!" },
  });
}

it("サイト内で入力を受け付け、処理中の重複送信を防いでMFAへ進む", async () => {
  const auth = adapter();
  let finish!: (value: SignInStep) => void;
  auth.signIn.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  render(<Login auth={auth} />);
  enterCredentials();
  fireEvent.click(screen.getByRole("button", { name: "パスワードを表示" }));
  expect(
    screen.getByLabelText("パスワード", { exact: true }).getAttribute("type"),
  ).toBe("text");
  fireEvent.click(screen.getByRole("button", { name: "ログイン" }));
  expect(auth.signIn).toHaveBeenCalledWith(
    "owner@example.test",
    "ExamplePassword1!",
  );
  expect(
    screen
      .getByRole("button", { name: "確認しています…" })
      .hasAttribute("disabled"),
  ).toBe(true);
  expect(auth.signIn).toHaveBeenCalledTimes(1);
  await act(async () => finish({ kind: "code", channel: "認証アプリ" }));
  expect(screen.queryByLabelText("パスワード", { exact: true })).toBeNull();
  fireEvent.change(screen.getByLabelText("確認コード"), {
    target: { value: "012345" },
  });
  fireEvent.click(screen.getByRole("button", { name: "コードを確認" }));
  await vi.waitFor(() =>
    expect(auth.confirmSignIn).toHaveBeenCalledWith("012345"),
  );
});

it("認証エラーの内部情報を出さず、パスワードを消して再入力できる", async () => {
  const auth = adapter();
  auth.signIn.mockRejectedValue(
    Object.assign(new Error("internal-sensitive-detail"), {
      name: "NotAuthorizedException",
    }),
  );
  render(<Login auth={auth} />);
  enterCredentials();
  fireEvent.click(screen.getByRole("button", { name: "ログイン" }));
  expect((await screen.findByRole("alert")).textContent).toContain(
    "正しくありません",
  );
  expect(screen.queryByText("internal-sensitive-detail")).toBeNull();
  expect(
    (screen.getByLabelText("パスワード", { exact: true }) as HTMLInputElement)
      .value,
  ).toBe("");
});

it("再設定をユーザーが選んだときだけコードを送り、確認後はログインへ戻す", async () => {
  const auth = adapter();
  render(<Login auth={auth} />);
  expect(auth.resetPassword).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "パスワードを忘れた方" }));
  fireEvent.change(screen.getByLabelText("メールアドレス / ユーザー名"), {
    target: { value: "owner@example.test" },
  });
  fireEvent.click(screen.getByRole("button", { name: "確認コードを送信" }));
  await screen.findByLabelText("確認コード");
  expect(auth.resetPassword).toHaveBeenCalledWith("owner@example.test");
  fireEvent.change(screen.getByLabelText("確認コード"), {
    target: { value: "123456" },
  });
  fireEvent.change(screen.getByLabelText("新しいパスワード", { exact: true }), {
    target: { value: "NewPassword1!" },
  });
  fireEvent.change(screen.getByLabelText("新しいパスワード（確認）"), {
    target: { value: "Mismatch1!" },
  });
  fireEvent.click(screen.getByRole("button", { name: "パスワードを設定" }));
  expect((await screen.findByRole("alert")).textContent).toContain(
    "一致していません",
  );
  expect(auth.confirmResetPassword).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText("新しいパスワード（確認）"), {
    target: { value: "NewPassword1!" },
  });
  fireEvent.click(screen.getByRole("button", { name: "パスワードを設定" }));
  await screen.findByRole("button", { name: "ログイン" });
  expect(auth.confirmResetPassword).toHaveBeenCalledWith(
    "owner@example.test",
    "123456",
    "NewPassword1!",
  );
  expect(screen.getByRole("status").textContent).toContain(
    "パスワードを変更しました",
  );
});
