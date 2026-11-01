const titles: Record<string, string> = {
  DNS_FAILURE: "対象サイトのIPアドレスを取得できませんでした",
  TLS_CERTIFICATE: "HTTPS証明書を検証できませんでした",
  TLS_HANDSHAKE: "HTTPS通信を開始できませんでした",
  CONNECT_TIMEOUT: "対象サイトへの接続が時間切れになりました",
  RESPONSE_TIMEOUT: "対象サイトの応答が時間切れになりました",
  FETCH_TIMEOUT: "ページの取得が時間切れになりました",
  CONNECTION_REFUSED: "対象サイトに接続を拒否されました",
  NETWORK_UNREACHABLE: "診断サーバーから対象サイトへ到達できませんでした",
  CONNECTION_FAILED: "対象サイトとの接続に失敗しました",
  HTTP_STATUS: "対象サイトから正常なページが返りませんでした",
};

export function ScanFailure({
  message,
  code,
}: {
  message: string;
  code?: string | null;
}) {
  const legacy =
    message === "接続・DNS・TLS検証に失敗しました（証明書検証は有効）";
  return (
    <div className="notice error" role="alert">
      <strong>
        {legacy
          ? "診断先ページを取得できませんでした"
          : titles[code || ""] || "診断を完了できませんでした"}
      </strong>
      <p>
        {legacy
          ? "診断サーバーが対象サイトのページを取得できず、結果を作成できませんでした。この記録には、DNS・通信・証明書のどこで失敗したかの詳細がありません。"
          : message}
      </p>
      <small>
        診断が完了していないため、対象サイトの安全性は判定していません。
      </small>
    </div>
  );
}
