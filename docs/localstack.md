# LocalStack対応・実行状況

確認日: 2026-10-31。固定イメージ案: localstack/localstack-pro:2026.3.0。
2026-11-01、Rancher Desktop起動・LocalStack認証・REST API(v1)経由のブラウザ診断E2Eを確認。
採用プランで必要機能が利用できることを実行前に確認する。無料利用可能と仮定しない。

| 対象 | 利用API/連携 | 状況 |
|---|---|---|
| DynamoDB | Query/GetItem/TransactWriteItems/GSI/Streams | MotoおよびLocalStackのブラウザ診断経路で確認 |
| SQS | SendMessage/Lambda event mapping/DLQ | LocalStackでSQSから診断Lambdaを実行し結果表示まで確認 |
| S3 | PutObject/GetObject/暗号化/Lifecycle | Put/GetをMotoおよびLocalStackのブラウザ診断経路で確認 |
| Lambda / API Gateway | Python3.13 zip/REST API payload v1/Mangum | CDK synthおよびREST API payload v1の実連携を確認 |
| Streams / EventBridge | 配送イベント/定期復旧 | Streams→配送Lambda→SQSの実経路を確認。EventBridgeの障害復旧実機テストは未実施。 |

CognitoはKeycloakへ置換し、署名付きトークンを検証する。ローカルはCode + PKCE、本番の自作画面はCognito SRP。
各環境で発行されるトークンに合わせて必要scopeを切り替える。CloudFrontはローカルViteへ置換。
IAMの強制、TLS、遅延、容量、スロットリング、原子的競合はMoto成功だけでは保証できない。

ホスト→LocalStack localhost:4566 / ホスト→Keycloak localhost:8080。
Lambda→LocalStack localstack:4566 / Lambda→Keycloak identity:8080（JWKS）。
issuerはブラウザ視点のlocalhost:8080。JWKSのみ内部接続先へ分離。
Lambda→fixture.security-testing.testは固定172.30.0.10、80番。
ブラウザからfixtureへはlocalhost:8081。診断登録URLにはlocalhost:8081を指定しない。

Composeはローカル開発用。fixtureはinternalなsecurity-testing-fixturesネットワークだけに配置。
runtime側172.30.0.10の専用Nginxゲートウェイが、隔離側172.31.0.10のfixtureだけへGET/HEADを中継。
ゲートウェイのIP転送は禁止し、別ホストへのプロキシ利用は拒否。固定IP許可はfixtureホストとの組だけに適用。任意のプライベートIPは許可しない。
fixture→LocalStack/Keycloakの接続拒否と、ワーカー→固定ゲートウェイ→fixtureの取得成功を実機確認。
本番にはこの例外を含む設定を注入できない。
DockerソケットをLocalStackへ渡すため、信頼できる開発環境でのみ実行する。

公式資料:
https://docs.localstack.cloud/aws/getting-started/auth-token/
https://docs.localstack.cloud/aws/services/lambda/
https://docs.localstack.cloud/aws/connecting/infrastructure-as-code/aws-cdk/

## APIが応答しない場合（2026-11-01の修正）
認証付きAPIが応答せず、Lambda直接呼び出しも時間切れになる不具合を再現。
同じPython3.13 Linuxランタイムでスタックを採取し、botocoreのサービス定義探索中に停滞していることを確認した。
配布物に439サービス分の定義が入り、Rancher Desktop環境で初期化時間が増えていた。
`scripts/package_lambda.py` は実行で使うDynamoDB・S3・SQSの定義と共有設定だけを同梱する。
定義データは23MiBから1.7MiBへ縮小し、LinuxランタイムでSDK初期化3.41秒とDB読み取りを確認。
SDKのバージョン・署名検証・JWT検証・IAM条件は変更しない。
新しいAWSクライアントを追加する際は `RUNTIME_AWS_SERVICES` に追記する。
テストは標準の定義探索パスを無効にして、配布対象の定義だけで全クライアントが作成できることを検証する。
[botocoreの定義探索仕様](https://docs.aws.amazon.com/botocore/latest/reference/loaders.html)を参照。

fixtureとゲートウェイのNginx設定はディレクトリ単位で読み取り専用マウントする。
設定ファイルを置換したときに単一ファイルのマウントが古いinodeを参照し、`nginx -s reload` がENOENTになることを防ぐ。
この設定の反映にはstatelessなfixture・fixture-gatewayだけを再作成する。LocalStack・Keycloakや保存データは再作成しない。
