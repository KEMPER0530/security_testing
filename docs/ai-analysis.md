# AI分析の接続口（現在は工事中）

現在の攻撃シナリオ分析は、観測した設定とバージョン管理したルールに基づく処理です。
AIを使用した結果として表示しません。Reactの「AI分析」は工事中で、実行ボタンは無効です。
OpenAI SDK・APIキー・モデル・外部送信は今回の実装に含めていません。
環境変数にキーが存在しても、このリリースからOpenAIを呼び出す経路はありません。

## 既に用意した構造

- `application.ports.AiAnalyzer.analyze(report)` が将来の実装の境界です。
- 認証付き `GET /v1/scans/{job_id}/ai-analysis` は `under_construction`、`provider: openai`、`result: null` を返します。所有者の既存ジョブだけ参照でき、削除した履歴や対象は404です。
- OpenAPIとReactのクライアント型に工事中のレスポンスを含めています。実行を受け付けるPOSTはまだありません。

## 接続時の実装方針

Pythonのoutbound adapterからOpenAI Responses APIへ接続し、bootstrapでAiAnalyzerへ注入します。
OpenAIの [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) を使い、説明・被害・対策・参照したチェックIDのJSONスキーマで結果を取得する設計を想定しています。
SDKはPydanticのスキーマを指定できますが、分析内容の正確性は別途検証します。
未観測の脆弱性の断定や存在しないチェックIDを拒否し、AIの出力で観測結果・CVSS・診断の合否を上書きしません。
拒否・失敗・未完了も成功結果と区別します。

APIキーはPython側だけで扱い、AWS Secrets Manager等から取得し、ReactやGitHubの公開変数へ渡しません。
送信するのは認可された診断結果の必要な項目に限定し、トークン・Cookie値・取得HTML全文を含めません。
対象サイトから取得した文章を命令として扱わず、分析に実行権限や追加のサイト取得機能を与えません。
モデル選定、非同期実行、利用上限、保存期間、課金・送信条件の画面表示と実送信の承認は、AI接続を実装する段階で具体化します。
