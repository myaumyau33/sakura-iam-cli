# sakura-iam-cli

さくらのクラウド IAM API をサービスプリンシパル認証で操作する、Python製のCLIです。サービスプリンシパルキーの一括生成・登録に加え、サービスプリンシパル、プロジェクトAPIキー、IAMロール、プロジェクト、フォルダ、グループ、ユーザを操作できます。

- Python 3.12以上
- パッケージ管理・ビルド: [uv](https://docs.astral.sh/uv/)
- CLIフレームワーク: Typer
- RSA鍵・JWT署名: cryptography

API仕様は[さくらのクラウド IAM API](https://manual.sakura.ad.jp/api/cloud/portal/?api=iam-api)および[サービスプリンシパル](https://manual.sakura.ad.jp/cloud/controlpanel/service-principal.html#id8)を参照してください。

## セットアップ

```console
uv sync
cp settings.example.json settings.json
```

`settings.json`に、CLIの認証に使う既存サービスプリンシパルキーを設定します。

```json
{
  "default_profile": "default",
  "profiles": {
    "default": {
      "base_url": "https://secure.sakura.ad.jp/cloud/api/iam/1.0/",
      "project_id": "123456789012",
      "service_principal_id": "123456789012",
      "kid": "EXISTING_KEY_KID",
      "private_key": "/absolute/path/to/existing.private.pem"
    }
  }
}
```

`settings.json`と秘密鍵はGitへコミットしないでください。相対パスの`private_key`は`settings.json`のあるディレクトリを基準に解決されます。

リポジトリ内では次のどちらでも実行できます。

```console
./sakura-iam-cli --help
uv run sakura-iam-cli --help
```

別の設定ファイルやプロファイルを使う場合、サブコマンドより前に指定します。

```console
./sakura-iam-cli --settings settings.json --profile production project list
```

## ビルドとインストール

ソース配布物とwheelを作成します。

```console
uv build
```

成果物は`dist/`に生成されます。

```text
dist/
├── sakura_iam_cli-0.1.0-py3-none-any.whl
└── sakura_iam_cli-0.1.0.tar.gz
```

wheelをCLIツールとしてインストールする場合:

```console
uv tool install dist/sakura_iam_cli-0.1.0-py3-none-any.whl
sakura-iam-cli --help
```

変更後に再インストールする場合:

```console
uv build
uv tool install --force dist/sakura_iam_cli-0.1.0-py3-none-any.whl
```

開発中はビルドせず、`./sakura-iam-cli`または`uv run sakura-iam-cli`を利用できます。現在のビルド成果物はPython wheelであり、依存関係を内包した単一バイナリではありません。

## シェル補完

```console
sakura-iam-cli --install-completion
exec zsh
```

補完スクリプトを表示するだけの場合:

```console
sakura-iam-cli --show-completion
```

## 権限について

実行する操作に対応したロールを、認証用サービスプリンシパルへ事前に付与してください。

- ユーザ、グループ、2要素認証: IDポリシーの`identity-admin`（ID管理者）
- プロジェクト作成: 作成先フォルダ以上にIAMロール`project-creator`
- フォルダ操作: フォルダ階層以上にIAMロール`folder-admin`
- プロジェクトAPIキー: 対象プロジェクトでAPIキー操作を許可するロール
- IAMポリシー変更: 対象階層のポリシーを変更できる管理ロール

ユーザ・グループ管理はIAMロールではなくIDロールで認可されます。既存プロジェクトの`owner`だけでは、新しいプロジェクトの作成やユーザの作成はできません。

## コマンド一覧

```text
sakura-iam-cli
├── sp          サービスプリンシパル
├── sp-key      サービスプリンシパルキー
├── api-key     プロジェクトAPIキー
├── iam-role    IAMロールの参照
├── project     プロジェクト
├── folder      フォルダ
├── group       ユーザグループと所属ユーザ
└── user        ユーザ、メール、OTP、認証デバイス
```

各コマンドの詳細は`--help`で確認できます。

```console
sakura-iam-cli project --help
sakura-iam-cli sp-key upload-key --help
```

## サービスプリンシパル

```console
sakura-iam-cli sp list --project-id 123456789012
sakura-iam-cli sp create --name batch-worker --description "バッチ処理用"
sakura-iam-cli sp get 987654321098
sakura-iam-cli sp update 987654321098 --name new-name --description "更新後"
sakura-iam-cli sp delete 987654321098 --dry-run
sakura-iam-cli sp delete 987654321098
sakura-iam-cli sp token
```

`sp token`はアクセストークンを標準出力へ表示します。ログやシェル履歴への取り扱いに注意してください。

## サービスプリンシパルキー

異なるRSA鍵を10組生成します。秘密鍵は`0600`、公開鍵は`0644`で保存され、既存ファイルは上書きしません。

```console
sakura-iam-cli sp-key create --num 10 --bits 2048 --output-key-dir ./work
```

公開鍵を指定したサービスプリンシパルへ一括登録します。認証用SPとアップロード先SPは別々に指定できます。

```console
sakura-iam-cli sp-key upload-key \
  --service-principal-id 987654321098 \
  --key-dir ./work
```

APIレスポンスとアップロード先SP IDは`*.public.json`へ保存されます。この記録を使って一括操作できます。

```console
sakura-iam-cli sp-key list --service-principal-id 987654321098
sakura-iam-cli sp-key disable --key-dir ./work --dry-run
sakura-iam-cli sp-key disable --key-dir ./work
sakura-iam-cli sp-key enable --key-dir ./work
sakura-iam-cli sp-key delete --key-dir ./work --dry-run
sakura-iam-cli sp-key delete --key-dir ./work
```

`--continue-on-error`を指定すると、個別の鍵で失敗しても残りの処理を継続します。リモートキーを削除しても、ローカルの秘密鍵と公開鍵は削除しません。

## プロジェクトAPIキーとIAMロール

有効なIAMロールIDを確認します。OpenAPIの`example`ではなく、このAPIが返す`id`を指定してください。

```console
sakura-iam-cli iam-role list --per-page 100
sakura-iam-cli iam-role get resource-viewer
```

APIキーを作成します。`--iam-role`は複数回指定できます。

```console
sakura-iam-cli api-key create \
  --name automation \
  --description "自動処理用" \
  --iam-role resource-viewer \
  --iam-role config-editor \
  --output ./work/automation-api-key.json
```

`--project-id`を省略するとプロファイルの`project_id`を使います。作成時に一度だけ返るシークレットを`--output`へ保存すると、ファイルは作成時点から`0600`になり、既存ファイルは上書きされません。シングルサーバ用APIキーでは`--server-resource-id`と`--zone-id`を両方指定してください。

```console
sakura-iam-cli api-key list --ordering=-name
sakura-iam-cli api-key get 111222333444
sakura-iam-cli api-key update 111222333444 \
  --name automation-new --description "更新後" --iam-role resource-viewer
sakura-iam-cli api-key delete 111222333444 --dry-run
sakura-iam-cli api-key delete 111222333444
```

## プロジェクト

```console
sakura-iam-cli project list --ordering=-code
sakura-iam-cli project create \
  --code automation-project \
  --name "Automation Project" \
  --description "自動処理用" \
  --parent-folder-id 112000000000
sakura-iam-cli project get 123456789012
sakura-iam-cli project update 123456789012 \
  --name "Updated Project" --description "更新後"
sakura-iam-cli project delete 123456789012 --dry-run
```

複数プロジェクトの移動:

```console
sakura-iam-cli project move \
  --project-id 123456789012 \
  --project-id 234567890123 \
  --parent-folder-id 112000000000
sakura-iam-cli project move --project-id 123456789012 --to-root --dry-run
```

## フォルダ

```console
sakura-iam-cli folder list --folder-name Production --parent-id 112000000000
sakura-iam-cli folder create \
  --name Production --description "本番環境用" --parent-id 112000000000
sakura-iam-cli folder get 223000000000
sakura-iam-cli folder update 223000000000 \
  --name Production-New --description "更新後"
sakura-iam-cli folder delete 223000000000 --dry-run
```

作成時に`--parent-id`を省略するとルートへ作成します。移動時は`--parent-id`または`--to-root`のどちらか一方を指定します。

```console
sakura-iam-cli folder move \
  --folder-id 223000000000 \
  --folder-id 224000000000 \
  --parent-id 112000000000
sakura-iam-cli folder move --folder-id 223000000000 --to-root
```

配下にフォルダまたはプロジェクトが残っているフォルダは削除できません。

## グループ

```console
sakura-iam-cli group list --ordering=-name
sakura-iam-cli group create --name Operators --description "運用担当者"
sakura-iam-cli group get 1
sakura-iam-cli group update 1 --name Operators-New --description "更新後"
sakura-iam-cli group delete 1 --dry-run
sakura-iam-cli group members 1
```

`set-members`は差分追加ではなく、所属ユーザ全体を置換します。

```console
sakura-iam-cli group set-members 1 \
  --user-id 111111111111 \
  --user-id 222222222222 \
  --dry-run
sakura-iam-cli group set-members 1 --clear
```

空指定による意図しない全解除を防ぐため、全ユーザを外す場合は`--clear`が必要です。

## ユーザ

ユーザ作成時、`--password-file`を省略するとパスワードを非表示で対話入力します。パスワードをコマンドラインへ直接渡すオプションはありません。

```console
sakura-iam-cli user list --ordering=-code
sakura-iam-cli user create --name User --code user-code --description "運用ユーザ"
sakura-iam-cli user create --name User --code user-code \
  --password-file /secure/path/password
sakura-iam-cli user get 111111111111
sakura-iam-cli user update 111111111111 --name User-New --description "更新後"
sakura-iam-cli user delete 111111111111 --dry-run
```

メール、OTP、信頼済みデバイス、WebAuthnセキュリティキー:

```console
sakura-iam-cli user register-email 111111111111 --email user@example.com
sakura-iam-cli user unregister-email 111111111111 --dry-run
sakura-iam-cli user deactivate-otp 111111111111 --dry-run
sakura-iam-cli user trusted-devices 111111111111
sakura-iam-cli user delete-trusted-device 111111111111 DEVICE_ID --dry-run
sakura-iam-cli user clear-trusted-devices 111111111111 --dry-run
sakura-iam-cli user security-keys 111111111111
sakura-iam-cli user get-security-key 111111111111 SECURITY_KEY_ID
sakura-iam-cli user delete-security-key 111111111111 SECURITY_KEY_ID --dry-run
```

## dry-run

削除、無効化、移動、所属ユーザの置換などの対応コマンドでは`--dry-run`を利用できます。dry-runでは認証やIAM API呼び出し、ローカルJSONの更新を行いません。

```console
sakura-iam-cli folder delete 223000000000 --dry-run
sakura-iam-cli project move --project-id 123456789012 --to-root --dry-run
```

## 開発

依存関係を同期し、テストを実行します。

```console
uv sync
uv run pytest
```

CLIとパッケージの簡易確認:

```console
uv run sakura-iam-cli --help
uv build
```
