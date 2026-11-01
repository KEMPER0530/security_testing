# AWSへの配信（汎用手順）

公開リポジトリには実際の公開URL、AWSアカウント、ホストゾーン、証明書、Cognitoプール、運用ログを含めません。

1. `infra/cdk/production.example.json`をGit管理外の`production.json`へコピーし、管理者の環境で実値を設定します。例の値でデプロイしないでください。
2. 初回だけ`make aws-initial AWS_PROFILE=<your-profile>`でFoundationとApplicationを構築します。
3. `make github-production AWS_PROFILE=<your-profile>`でGitHub production Environment Secretsを構成します。AWS固定アクセスキーは使用しません。
4. 通常はmainへのコード変更でPythonとReactを更新します。Foundationは再作成しません。
5. 手動更新は`make aws-app AWS_PROFILE=<your-profile>`。既存のデータ・認証基盤・配信基盤を保持します。

実値はチャット・PR・公開ドキュメントへ転記しません。GitHub OIDCの信頼は所有者とリポジトリのID、production環境に制限します。
Secretsから設定を読み込む処理は`scripts/write_production_config.py`、同期処理は`scripts/configure_github_production.py`です。
公開リポジトリのCIでは、ダミー設定によるsynthと検査だけを行います。

公開版やforkでは配信は既定で無効です。設定同期が全Secretsの保存に成功した後だけ、`PRODUCTION_DEPLOY_ENABLED`を有効にします。実環境の接続先は公開しません。
