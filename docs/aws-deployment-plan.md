# AWS本番移行の設計案

この文書は初期設計メモ。実装した構成とコマンドは[現行のAWS配信手順](aws-deployment.md)を参照。

2026-11-01。以下は次の実装に向けた設計案。現時点のCDKは単一のSecurityStackであり、
スタック分割・本番用配信手順・CI/CDは未実装。AWSへのデプロイは実施していない。

## 初回構築と通常リリースの分離

| 区分 | 管理するもの | 実行するタイミング |
| --- | --- | --- |
| CDK bootstrap | CDK用アセット保管先・デプロイロール | AWSアカウントとリージョンごとの初回。将来必要な場合のみ更新 |
| FoundationStack（予定） | Cognito、DynamoDB、レポートS3、SQS/DLQ、フロント配信用S3/CloudFront、必要な送信経路 | 初回構築と、基盤設定を変更するとき |
| ApplicationStack（予定） | Python Lambda、API Gateway、イベント連携、アプリ権限とアラーム | 初回とアプリ更新時。変更のないリソースは再作成しない |
| フロント配信 | Reactのビルド成果物、接続設定、CloudFrontキャッシュ更新 | 初回とフロント更新時 |

通常リリースではFoundationStackをデプロイ対象に含めない。
ApplicationStackからFoundationStackを参照する一方向の依存にし、循環参照を避ける。
API URLなどの出力を使ってフロントの本番設定を確定する。
LambdaもCDKでコードを更新し、別の手動更新処理と管理を競合させない。

「初回だけ」は通常のアプリ更新で基盤を作り直さないという意味。
認証設定・保持期間・ネットワークなどを変更する場合には、既存基盤をCDKで更新する。
Cognitoと永続データの削除保護・保持設定、差分確認、ロールバック手順も整備する。

## Cognitoログイン

ReactはCognitoのマネージドログインへ遷移し、公開クライアントのAuthorization Code + PKCEを使う。
ブラウザへクライアントシークレットを配置しない。
本番ドメインに合わせてコールバックURL・ログアウトURL・CORSを固定する。
現行のJWT署名・issuer・client・有効期限・scopeの検証を維持し、Cognitoで実機確認する。
現在のローカルKeycloak向けOIDC設定をそのまま本番へ流用せず、Cognitoのエンドポイント設定を用意する。

## 公開サイト診断の開始条件（最新指示）
所有確認と事前重要度質問票は廃止。公開URL登録後に診断を開始できる。
Cognitoログインと利用者ごとのデータ分離は維持する。
公開ページの低負荷GETと既存のSSRF防御・レート制限の範囲で実行する。
問題は診断後に暫定深刻度・対応優先度で表示する。CVSSは根拠が不足する場合未評価。

## 実装前に確定する情報

1. 利用するAWS CLIプロファイルとリージョン（候補は東京）。アクセスキーはチャットへ記載しない。
2. 公開ドメインとDNS管理先。既存サイトと異なるサブドメインを使うか。
3. 利用者の範囲（本人・社内・一般公開）と診断対象の範囲。
4. リリース方法（ローカルCLIまたはGitHub Actions）。Actionsの場合はOIDC連携する。
5. 月額予算と想定する利用者数・診断回数。送信制御方式の選定に使う。

## 本番移行の完了条件

LocalStackとは別に、Cognitoログイン・ユーザー間の認可・非同期診断・イベント復旧をAWSで検証する。
送信先制御、通知先、データ保護、費用上限の監視を確定する。
基盤構築後に、アプリだけの2回目リリースでユーザーと診断データが維持されることを確認する。
未実装・未検証の一覧は[実装状況](status.md)と[運用とAWS移行](operations.md)を参照する。

一次資料（確認日2026-11-01）:
[CDK bootstrap](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-env.html)、
[Cognito PKCE](https://docs.aws.amazon.com/cognito/latest/developerguide/using-pkce-in-authorization-code.html)。
