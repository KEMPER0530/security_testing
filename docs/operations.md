# 運用・脅威・AWS移行

## 脅威と対策
SSRF: HTTP(S)の標準ポートのみ、全DNS応答の公開性を検証、検証したIPへ直接接続。
SNI/Hostは対象名のまま。証明書検証を無効化せず、リダイレクトは拒否。環境プロキシ不使用。
公開IPを検証後に再解決しない。DNSの解決時間はOS依存。
XSS: Reactテキスト出力、レポートのhtml.escape、HTMLレポートCSP default-src none。
認可: ownerはJWTのsubのみ。全DBキーをowner内へ限定。レポートもjobと対象を認可して取得。
機微情報: Cookie値・HTTPヘッダー値・HTML本文は保存せず観測した状態のみ保存。
URLはクエリを拒否。パス自体に秘密を含める対象は登録しない。

## 復旧
配送: 未配送Outboxを定期再送。SQS送信後の記録失敗は重複で吸収。
実行:90秒リース、60秒Lambda、ホスト120秒待機、最大3回。SQS visibility360秒、最大5受信でDLQ。
EventBridgeは2分ごとに未配送・QUEUED・期限切れRUNNINGを再通知。
DLQ・Lambdaエラー・キュー滞留のアラームを作成。通知先SNS/メール連携は未設定。
DLQの再投入前にjobのstate、attempt、対象の許可状態を確認する。
全削除操作は利用者確認後に実施。対象削除は現状tombstoneと結果参照拒否。
ジョブと削除済み対象は30日TTL、S3は30日、監査90日、冪等性キー24時間。即時物理削除の全ユーザーデータ削除ジョブは未実装。
削除済み対象のジョブは一覧から除外する。

## AWS公開後の運用整備・残検証
初回公開と通常リリースは[現在のAWS配信手順](aws-deployment.md)を参照。
ローカルの統合E2Eを成功させ、AWS開発アカウントでIAM・JWT・SQS・Streams・イベント復旧を再検証する。
本番送信先制御は未構築。LambdaをVPC内へ置き、送信経路とDNSを制御する案を審査する。
SG単体ではドメイン制御できない。NAT/プロキシ/Firewallの料金と送信制御を検討する。
Cognitoの専用クライアント・ドメイン・グループ、独自ドメイン、CloudFront配信は構成済み。
実ユーザーのログイン完了後の操作と、既存プールの他グループからの拒否を実機で確認する。
本番フロントはCognitoのOIDC metadataと専用ログアウト設定を使用。ローカルKeycloak設定を流用しない。
DynamoDB権限はGetItem、Query、トランザクション内のPutItemへ限定（EnclosingOperation条件）。実AWSでの操作別検証と所有者条件等の追加制約を検討する。
認証エンドポイントの負荷対策、監視通知先、データ保持・削除方針を確定する。

## 費用前提
試算シナリオ:利用者10名、月1,000診断、1ページ256KiB以下、Lambda512MiB/診断15秒以内、レポート30日、ログ30日。
月の診断Lambdaは上限7,500GB秒程度、加えてAPI・配送・復旧Lambda、DynamoDB、S3、SQS、CloudWatch、Cognito、CloudFrontを含む。
NATやFirewallを採用すると固定費が主体となり得る。無料枠適用はアカウント条件に依存。
2026-11-01に東京のLambda/REST API単価を公式料金JSONで確認。API/Lambda部分の参考試算はcost.mdを参照。送信制御を含む全体額は未確定。
LocalStackのプラン費用はAWSと別。採用プランに応じ確認する。
料金確認先: https://calculator.aws/ / https://www.localstack.cloud/pricing

権限の根拠: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html （確認日2026-11-01）
