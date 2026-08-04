# sakura-iam-cli

さくらのクラウド IAM API のサービスプリンシパルキーを、まとめて生成・登録する小さなCLIです。

## セットアップ

```console
uv sync
cp settings.example.json settings.json
```

`settings.json` を編集します。`private_key` は、IAM操作権限を持つ既存サービスプリンシパルキーの秘密鍵です。設定ファイルと秘密鍵はGitへコミットしないでください。

## 鍵を10組生成

```console
./sakura-iam-cli sp-key create --num 10 --output-key-dir ./work
```

RSA 2048bit（`--bits 3072` / `4096` も指定可能）の異なる鍵を生成します。秘密鍵は `0600`、公開鍵は `0644` です。既存ファイルは上書きしません。

## 公開鍵を一括アップロード

```console
./sakura-iam-cli --settings settings.json sp-key upload-key \
  --service-principal-id 987654321098 \
  --key-dir ./work
```

プロファイル内の既存SPキーでJWTを署名してアクセストークンを発行し、`--service-principal-id` で指定したSPへ `*.public.pem` を順番に登録します。認証に使うSPとアップロード先のSPは別々に指定できます。APIレスポンス（KIDなど）とアップロード先SP IDは、各公開鍵の隣に `*.public.json` として保存します。途中の失敗後も続行する場合は `--continue-on-error` を付けます。

## 登録したキーを一括削除

```console
./sakura-iam-cli --settings settings.json sp-key delete --key-dir ./work
```

`*.public.json` に記録されたキーIDを使って、IAM上のキーを削除します。削除済みのJSONは `status: deleted` に更新され、再実行時はスキップされます。秘密鍵・公開鍵などのローカルファイルは削除しません。途中の失敗後も続行する場合は `--continue-on-error` を付けます。

実際に削除せず対象だけを確認するには `--dry-run` を指定します。この場合は認証やAPI呼び出し、JSONの更新を行いません。

```console
./sakura-iam-cli sp-key delete --key-dir ./work --dry-run
```

## 登録したキーの無効化・有効化

```console
./sakura-iam-cli --settings settings.json sp-key disable --key-dir ./work
./sakura-iam-cli --settings settings.json sp-key enable --key-dir ./work
```

work内のアップロード結果JSONを使ってIAM上のキーを一括操作し、成功後はJSONの `status` を `disabled` または `enabled` に更新します。すでに目的の状態になっているキーと削除済みキーはスキップします。どちらも `--dry-run` と `--continue-on-error` に対応しています。

別プロファイルは `--profile PROFILE_NAME` で選べます。コマンド全体のヘルプは `./sakura-iam-cli --help` で表示できます。`uv run sakura-iam-cli ...` でも同じように実行できます。

## 開発

```console
uv run pytest
```

API仕様: [さくらのクラウド IAM API](https://manual.sakura.ad.jp/api/cloud/portal/?api=iam-api) / [サービスプリンシパル](https://manual.sakura.ad.jp/cloud/controlpanel/service-principal.html#id8)

## サービスプリンシパル操作

```console
# 一覧（project-id、page、per-page、orderingで絞り込み可能）
./sakura-iam-cli sp list --project-id 123456789012

# 作成（project-id省略時はプロファイルのproject_idを利用）
./sakura-iam-cli sp create --name batch-worker --description "バッチ処理用"

# 取得・更新・削除
./sakura-iam-cli sp get 987654321098
./sakura-iam-cli sp update 987654321098 --name new-name --description "更新後"
./sakura-iam-cli sp delete 987654321098 --dry-run
./sakura-iam-cli sp delete 987654321098

# 設定中のSPキーでアクセストークンを発行
./sakura-iam-cli sp token

# 指定SPのキー一覧
./sakura-iam-cli sp-key list --service-principal-id 987654321098
```

## プロジェクトAPIキー操作

```console
# 一覧
./sakura-iam-cli api-key list --page 1 --per-page 100 --ordering=-name

# 作成（--iam-roleは複数回指定可能）
./sakura-iam-cli iam-role list --per-page 100

./sakura-iam-cli api-key create \
  --name automation \
  --description "自動処理用" \
  --iam-role resource-viewer \
  --output ./work/automation-api-key.json

# 取得・更新
./sakura-iam-cli api-key get 111222333444
./sakura-iam-cli api-key update 111222333444 \
  --name automation-new \
  --description "更新後" \
  --iam-role resource-viewer

# 削除対象の確認・削除
./sakura-iam-cli api-key delete 111222333444 --dry-run
./sakura-iam-cli api-key delete 111222333444
```

作成時の `--project-id` を省略するとプロファイルの `project_id` を使います。`--iam-role`には `iam-role list`で取得できるロールの`id`を指定してください。`--output`を指定すると、作成時に一度だけ返されるアクセストークンシークレットを含むレスポンスを権限`0600`で保存し、既存ファイルは上書きしません。シングルサーバ用APIキーでは `--server-resource-id` と `--zone-id` を両方指定してください。

## IAMロールの確認

```console
./sakura-iam-cli iam-role list --page 1 --per-page 100
./sakura-iam-cli iam-role get resource-viewer
```

## プロジェクト操作

```console
# 一覧（--iam-roleは複数回指定可能）
./sakura-iam-cli project list \
  --iam-role resource-viewer \
  --parent-folder-id 112000000000 \
  --ordering=-code

# 作成・取得・更新
./sakura-iam-cli project create \
  --code automation-project \
  --name "Automation Project" \
  --description "自動処理用" \
  --parent-folder-id 112000000000
./sakura-iam-cli project get 123456789012
./sakura-iam-cli project update 123456789012 \
  --name "Updated Project" --description "更新後"

# 削除対象確認・削除
./sakura-iam-cli project delete 123456789012 --dry-run
./sakura-iam-cli project delete 123456789012

# 複数プロジェクトをフォルダへ移動
./sakura-iam-cli project move \
  --project-id 123456789012 \
  --project-id 234567890123 \
  --parent-folder-id 112000000000

# ルートへ移動（事前確認）
./sakura-iam-cli project move \
  --project-id 123456789012 --to-root --dry-run
```

## フォルダ操作

```console
# 一覧・作成・取得・更新
./sakura-iam-cli folder list --folder-name Production --parent-id 112000000000
./sakura-iam-cli folder create \
  --name Production --description "本番環境用" --parent-id 112000000000
./sakura-iam-cli folder get 223000000000
./sakura-iam-cli folder update 223000000000 \
  --name Production-New --description "更新後"

# 空のフォルダを削除
./sakura-iam-cli folder delete 223000000000 --dry-run
./sakura-iam-cli folder delete 223000000000

# 複数フォルダを別のフォルダへ移動
./sakura-iam-cli folder move \
  --folder-id 223000000000 \
  --folder-id 224000000000 \
  --parent-id 112000000000

# ルートへ移動
./sakura-iam-cli folder move --folder-id 223000000000 --to-root
```

フォルダ作成時に`--parent-id`を省略するとルートへ作成します。移動時は`--parent-id`または`--to-root`のどちらか一方を指定してください。削除対象の配下にフォルダまたはプロジェクトが残っている場合、IAM APIが削除を拒否します。

## グループ操作

```console
# 一覧・作成・取得・更新・削除
./sakura-iam-cli group list --ordering=-name
./sakura-iam-cli group create --name Operators --description "運用担当者"
./sakura-iam-cli group get 1
./sakura-iam-cli group update 1 --name Operators-New --description "更新後"
./sakura-iam-cli group delete 1 --dry-run
./sakura-iam-cli group delete 1

# 所属ユーザを確認
./sakura-iam-cli group members 1

# 所属ユーザ全体を置換
./sakura-iam-cli group set-members 1 \
  --user-id 111111111111 \
  --user-id 222222222222

# 全ユーザをグループから外す
./sakura-iam-cli group set-members 1 --clear
```

`set-members`は指定ユーザの追加ではなく、グループの所属ユーザ全体を置換します。変更前の確認には`--dry-run`を使用できます。全解除には意図しない空指定を避けるため`--clear`が必要です。

## ユーザ操作

```console
# 一覧・作成・取得・更新・削除
./sakura-iam-cli user list --ordering=-code
./sakura-iam-cli user create --name User --code user-code --description "運用ユーザ"
./sakura-iam-cli user get 111111111111
./sakura-iam-cli user update 111111111111 --name User-New --description "更新後"
./sakura-iam-cli user delete 111111111111 --dry-run

# 非対話環境ではパスワードファイルを使用
./sakura-iam-cli user create --name User --code user-code \
  --password-file /secure/path/password

# メールアドレス
./sakura-iam-cli user register-email 111111111111 --email user@example.com
./sakura-iam-cli user unregister-email 111111111111

# OTP・信頼済みデバイス
./sakura-iam-cli user deactivate-otp 111111111111 --dry-run
./sakura-iam-cli user trusted-devices 111111111111
./sakura-iam-cli user delete-trusted-device 111111111111 DEVICE_ID
./sakura-iam-cli user clear-trusted-devices 111111111111

# WebAuthnセキュリティキー
./sakura-iam-cli user security-keys 111111111111
./sakura-iam-cli user get-security-key 111111111111 SECURITY_KEY_ID
./sakura-iam-cli user delete-security-key 111111111111 SECURITY_KEY_ID
```

ユーザ作成時、`--password-file`を省略するとパスワードを非表示で対話入力します。更新時に`--password-file`を指定した場合のみパスワードを変更します。削除・OTP無効化・デバイス削除・メール解除には`--dry-run`を利用できます。
