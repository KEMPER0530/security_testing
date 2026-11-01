# AWS費用の前提と参考試算

確認日: 2026-11-01。東京(ap-northeast-1)、USD、税・為替・無料枠を含めない参考値。
実AWSへのデプロイや請求の発生は行っていません。

## 小規模運用の例

利用者10名、月1,000診断、1ページ256KiB以内、API呼出し20回/診断、レポート30日。
512MiBのLambdaを使い、診断15秒、API0.2秒、配送0.1秒、復旧0.1秒/回と仮定。
復旧は2分間隔のため30日で21,600回。API20,000回、配送1,000回、診断1,000回。

| 計算対象 | 数量 | 月額参考 |
|---|---:|---:|
| 診断Lambda実行時間 | 7,500 GB秒 | $0.1250 |
| API Lambda実行時間 | 2,000 GB秒 | $0.0333 |
| 配送Lambda実行時間 | 50 GB秒 | $0.0008 |
| 復旧Lambda実行時間 | 1,080 GB秒 | $0.0180 |
| Lambda呼出し | 43,600回 | $0.0087 |
| API Gateway REST API | 20,000回 | $0.0850 |

上記API・Lambdaのみの小計は約$0.271/月です。サービス全体の見積額ではありません。
初期化、再試行、長時間診断、利用量の増加は別途加算されます。

## 別途必要な費用

DynamoDBのトランザクション・GSI・履歴・バックアップ、S3の保存/リクエスト、SQSのポーリング、
CloudWatchのログとアラーム、Cognito、CloudFront、DNS/ドメインを加算します。
本番送信制御の構成が未確定のため、NAT Gateway/送信プロキシ/Firewallの固定費も未確定です。
LocalStackのプランはAWSとは別料金。現在の契約を変更したり購入したりしていません。

全体の金額は、送信制御、ログ量、アラーム、保存量を確定後にAWS Pricing Calculatorで算定します。
無料枠が使えるとは仮定していません。REST APIとHTTP APIは単価が異なります。

## 公式単価

Lambda x86の最初の段階: $0.0000166667/GB秒、$0.20/100万呼出し。
REST API: 最初の3.33億リクエストは$4.25/100万回。
公式公開料金JSONのpublicationDateはLambda 2026-10-30、API Gateway 2026-10-13。

[AWS Lambda東京リージョン公式料金JSON](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSLambda/current/ap-northeast-1/index.json)
[AWS API Gateway東京リージョン公式料金JSON](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonApiGateway/current/ap-northeast-1/index.json)
[AWS Pricing Calculator](https://calculator.aws/)
