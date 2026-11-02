security_testing システム構成とデプロイ
更新日: 2026-11-02

1. AWSのシステム構成

  利用者（PC・スマートフォン）
    |-- DNS問い合わせ --> Route 53（既存ゾーンにAliasを追加）
    |-- HTTPS ----------> CloudFront -- OAC --> 非公開S3（React配信資産）
    |                       ^
    |                       +-- 既存ACM証明書（us-east-1）
    |-- 自作画面 / SRP --> Cognito（既存User Pool / 専用client・group）
    |
    +-- Bearer JWT ------> API Gateway REST API
                            |
                            v
                         API Lambda（Python / FastAPI）
                            |-- JWT署名・期限・client・scope・groupの検証
                            |-- 公開URL登録・診断受付・利用者ごとの認可
                            |-- 診断状態とレポートの参照・履歴からの日本語PDF取得・対象と履歴の論理削除
                            v
                         DynamoDB（Job + Outboxをトランザクションで保存）
                            |
                            v
                         DynamoDB Streams（Outbox INSERT）
                            |
                            v
                         Dispatcher Lambda（Python）
                            |
                            v
                         SQS --------------------> SQS DLQ（規定回数失敗後）
                            |
                            v
                         Worker Lambda（Python / 非同期診断 / 同時実行2）
                            |-- 登録した公開サイトをHTTP(S) GET
                            |   公開IP検証・検証済みIPへの接続固定・TLS検証
                            |-- 非公開S3へレポート保存
                            +-- DynamoDBへ状態・確定レポートの参照先を保存

  EventBridge（2分ごと）--> Recovery Lambda（Python）
                            |-- DynamoDBのGSIで未配送・実行期限切れを検索
                            +-- SQSへ再通知

  CloudWatch: 4 Lambdaのログ・エラーとSQS滞留・DLQを監視。
  診断レポートは公開せず、APIで所有者を認可して返す。
  診断後に問題を暫定深刻度（高・中・低）の順に表示。追加条件を明記してCVSS v4.0を参考採点。採点対象外・未実施は区別。

2. Pythonバックエンドの4つのLambda

  API         : FastAPI。対象登録・診断受付・結果参照。
  Dispatcher  : OutboxをSQSへ配送。
  Worker      : サイト診断、レポート保存、結果の確定。
  Recovery    : 未配送や実行リース切れを検索して再通知。

  クリーンアーキテクチャの依存方向は adapters -> application -> domain。
  Domain/ApplicationはAWS SDKやWebフレームワークに依存しない。

3. AWSへの配信方針

  初回はFoundationとApplicationを構築する。
  通常更新はPythonとReactを更新し、Foundationは再作成しない。
  接続先・アカウント・認証ID・証明書・配信用権限など、実環境の情報はこの文書に記載しない。
  実環境固有の設定はGit管理外で保持し、配信時だけGitHub Environment Secretsから読み込む。

4. 編集用構成図と検証状況

  docs/diagrams/aws-architecture.drawio   : draw.io編集用。構成・配信の2ページ。
  docs/diagrams/aws-architecture.svg      : AWSシステム構成図。
  docs/diagrams/application-deployment.svg: Python + Reactの通常配信図。
  README.md                             : GitHubで画像を表示するREADME。
  docs/verification.md / docs/status.md  : 実機検証記録と残作業。

  LocalStackはKeycloak（Code + PKCE）と隔離したテストサイトを使用。
  本番はReactの自作フォームからCognitoへSRP認証。パスワードをPythonへ送らない。
  AWS公開済みでも、ユーザーのログイン後の実サイト診断は未検証。
  本番送信経路制御、通知先、CVSS手動採点等の残作業はstatus.mdを参照。

追加機能（2026-11-02）:
  診断履歴の各行から日本語PDFを取得。対象・履歴の削除は確認後に参照を停止する。
  全チェックに平易な説明・判定根拠・出典を表示し、CVSS v4.0の条件付き参考評価を行う。
  設定観測から攻撃シナリオを分類し、注意箇所・被害・追加条件・対策を画面とPDFへ出力する。
  AI分析は工事中。将来のOpenAI接続口だけを定義し、外部AIへ送信しない。

追加診断とIPA参照の診断レポート
  常時表示される5種類のカードからWeb・限定Web検証・ネットワーク・AWSホスト・AWSクラウドを選択。
  種類に応じて検査内容・結果・履歴を切り替え、異なる種類の結果を混在させない。
  Workerは読み取り専用ロールをSTSで引き受け、指定リソースの設定・SSM/Inspector収集情報を確認。
  AWSホスト/クラウドは対象AWS管理者による接続ロール作成が必要。包括的な侵入実証は未対応。
  PDFは診断結果・根拠・改善方法と、IPA資料の節との対応・未実施範囲を表で表示。詳しくはdocs/diagnostic-profiles.md。
