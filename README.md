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
