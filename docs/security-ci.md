# Security checks

`.github/workflows/security.yml`をpush・PR・手動実行で使用します。Go向け処理はこのPython/Reactリポジトリには追加しません。

1. Python / JavaScript / TypeScriptをCodeQL security-extendedで検査。PythonはBanditも実行します。
2. Gitleaksで全Git履歴を検査。PRへの自動コメントと検出情報の自動アップロードは無効です。
3. Trivyでソースの依存関係・秘密情報・設定、CDKが生成したCloudFormationを検査します。
4. pnpm auditはmoderate以上、pip-auditはロックしたPython実行・開発依存の脆弱性を検査します。
5. 既存のテスト・型・lint・ビルド・OpenAPI生成差分・依存境界・Lambdaパッケージ検査を維持します。

書き込み権限はCodeQLのsecurity-eventsだけに限定し、各ジョブに制限時間を設定しています。
実運用の接続先を含む設定はGit管理外・GitHub Environment Secretsに保持します。
CIのCDK検査には`production.example.json`だけを使用します。

## Trivyの設計上の例外

例外は`.trivyignore.yaml`でFoundationテンプレートだけに限定し、期限を設けています。検査全体は無効化しません。

- CloudFrontのWAF: 公開する静的React資産を配信する経路です。認証APIへのアプリケーション上の制限とは別の対策であり、WAF導入はアクセス量と費用を確認して判断します。WAFがあると主張するものではありません。
- S3のCustomer Managed Key: 明示したAES256 SSE-S3・公開ブロック・TLS・IAM/OACを使用します。現在の要件はカスタマー管理KMS鍵を必須にしていません。保存時暗号化そのものは維持しています。

Trivy 0.76はCloudFormationの`SqsManagedSseEnabled`を認識せずSQSを未暗号化と判定するため、この指摘もFoundationに限定して例外化しています。`check_aws_infra.py`が全SQSキューの同属性がtrueであることを独立に必須検査します。SQSの保存時暗号化は省略せず、SQS管理鍵を明示します。新規のHIGH/CRITICAL指摘、秘密情報、依存脆弱性は失敗として扱います。
