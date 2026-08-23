# sakura-iam-cli

さくらのクラウド IAM API をサービスプリンシパル認証で操作する、Python製のCLIです。サービスプリンシパルキーの一括生成・登録に加え、サービスプリンシパル、プロジェクトAPIキー、IAMポリシー、IAMロール、IDポリシー、IDロール、組織、サービスポリシー、認証設定、プロジェクト、フォルダ、グループ、ユーザを操作できます。

- Python 3.12以上
- パッケージ管理・ビルド: [uv](https://docs.astral.sh/uv/)
- CLIフレームワーク: Typer
- RSA鍵・JWT署名: cryptography

API仕様は[さくらのクラウド IAM API](https://manual.sakura.ad.jp/api/cloud/portal/?api=iam-api)および[サービスプリンシパル](https://manual.sakura.ad.jp/cloud/controlpanel/service-principal.html#id8)を参照してください。

## セットアップ

```console
uv sync
install -m 600 settings.example.json settings.json
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

`settings.json`と秘密鍵はGitへコミットせず、所有者だけが読める権限（`0600`または`0400`）にしてください。CLIは権限が広すぎるファイルを拒否します。相対パスの`private_key`は`settings.json`のあるディレクトリを基準に解決されます。API URLはHTTPSに限定され、ローカル開発用のloopbackアドレスに限りHTTPも利用できます。

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
├── sakura_iam_cli-0.10.0-py3-none-any.whl
└── sakura_iam_cli-0.10.0.tar.gz
```

wheelをCLIツールとしてインストールする場合:

```console
uv tool install dist/sakura_iam_cli-0.10.0-py3-none-any.whl
sakura-iam-cli --help
```

変更後に再インストールする場合:

```console
uv build
uv tool install --force --reinstall dist/sakura_iam_cli-0.10.0-py3-none-any.whl
```

開発中はビルドせず、`./sakura-iam-cli`または`uv run sakura-iam-cli`を利用できます。現在のビルド成果物はPython wheelであり、依存関係を内包した単一バイナリではありません。

## シェル補完

シェル補完は`PATH`上の`sakura-iam-cli`を呼び出すため、リポジトリ内の`./sakura-iam-cli`ランチャーだけでは利用できません。最初にCLIをツールとしてインストールします。

```console
uv tool install --force --reinstall .
rehash
command -v sakura-iam-cli
sakura-iam-cli --install-completion
exec zsh
```

`command -v`でパスが表示されない場合、uvのツール用binディレクトリを`PATH`へ追加してください。uvから案内を表示・設定するには次を実行します。

```console
uv tool update-shell
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
├── iam-policy  組織・フォルダ・プロジェクトのIAMポリシー
├── id-role     IDロールの参照
├── id-policy   組織IDポリシーの参照・更新
├── organization 組織情報の参照・更新
├── service-policy サービスポリシーの管理
├── auth        認証コンテキスト・組織認証設定
├── project     プロジェクト
├── folder      フォルダ
├── resource    フォルダとプロジェクトのパス操作
├── group       ユーザグループと所属ユーザ
├── provisioning SCIMユーザープロビジョニング
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

作成時に保存した認証情報で Cloud API v1.1 の `GET /auth-status` を呼び出し、
APIキーに紐づくプロジェクトや権限を確認できます。認証情報ファイルは `0600` である必要があります。

```console
sakura-iam-cli api-key auth-status ./work/automation-api-key.json --zone is1a
```

`--zone` は `tk1a`, `tk1b`, `is1a`, `is1b`, `is1c`, `tk1v` から選択します。

## IAMポリシー

組織、フォルダ、プロジェクトのいずれか1階層を指定してIAMポリシーを取得します。

```console
sakura-iam-cli iam-policy get --organization
sakura-iam-cli iam-policy get --folder-id 112000000000
sakura-iam-cli iam-policy get --project-id 123456789012
```

取得結果を編集し、同じ階層のIAMポリシー全体を置き換えます。更新前に`--dry-run`で対象階層とJSONを確認してください。

```console
sakura-iam-cli iam-policy get --project-id 123456789012 > iam-policy.json
sakura-iam-cli iam-policy update iam-policy.json \
  --project-id 123456789012 --dry-run
sakura-iam-cli iam-policy update iam-policy.json \
  --project-id 123456789012
```

```json
{
  "bindings": [
    {
      "role": {"type": "preset", "id": "owner"},
      "principals": [
        {"type": "user", "id": 111111111111},
        {"type": "group", "id": 1},
        {"type": "service-principal", "id": 222222222222}
      ]
    }
  ]
}
```

空の`bindings`を更新すると、その階層に直接設定されたIAMポリシーがすべて解除されます。上位階層から継承された権限は変更されません。

対話形式でユーザまたはサービスプリンシパルへIAMロールを追加する場合は`add`を使います。

```console
sakura-iam-cli iam-policy add
sakura-iam-cli iam-policy add --organization
sakura-iam-cli iam-policy add --folder-id 112000000000
sakura-iam-cli iam-policy add --project-id 123456789012
sakura-iam-cli iam-policy add --project-id 123456789012 --dry-run
```

対話画面では次の順に複数選択します。

1. 対象階層（組織／フォルダ／プロジェクト）
2. 対象フォルダまたはプロジェクト
3. プリンシパル種別（サービスプリンシパル／ユーザ）
4. 追加するサービスプリンシパルまたはユーザ
5. 割り当てるIAMロール
6. 更新内容の確認

上下キーで移動し、Spaceで`[ ]`と`[x]`を切り替え、Enterで確定します。`--organization`、`--folder-id`、`--project-id`のいずれかを指定した場合は、対象階層の選択を省略できます。対象階層へ付与できないIAMロールは候補に表示されません。

選択した全プリンシパルに割り当て済みのIAMロールは、最初から`[x]`になります。複数選択のうち一部だけに割り当て済みの場合は「一部割当済み」と表示し、意図しない権限拡大を避けるため未選択にします。このコマンドは追加専用なので、既存ロールのチェックを外しても割り当ては削除されません。現在のIAMポリシーは保持され、選択した組み合わせだけが重複なく追加されます。`--dry-run`では一覧と現在のポリシーを取得して選択画面を表示しますが、更新APIは呼び出しません。

割り当てを対話形式で削除する場合は`delete`を使います。

```console
sakura-iam-cli iam-policy delete
sakura-iam-cli iam-policy delete --organization
sakura-iam-cli iam-policy delete --folder-id 112000000000
sakura-iam-cli iam-policy delete --project-id 123456789012 --dry-run
```

対象階層を選んだ後、その階層でIAMロールが直接割り当てられているSP／ユーザだけが候補に表示されます。プリンシパルを選ぶと、その対象に割り当てられているロールだけを削除候補として表示します。複数対象の一部だけが持つロールには「一部のみ割当済み」と表示されます。

削除候補のロールは安全のためすべて未選択で開始します。選択したプリンシパルとロールの組み合わせだけを削除し、空になったbindingは自動的に取り除きます。上位階層から継承された割り当てはこの操作の対象になりません。

## IDポリシーとIDロール

利用可能なIDロールを参照します。

```console
sakura-iam-cli id-role list --per-page 100
sakura-iam-cli id-role get identity-admin
```

組織のIDポリシーを取得、またはJSONファイルの内容で置き換えます。`update`はポリシー全体を置き換えるため、先に現在の内容を保存して編集してください。

```console
sakura-iam-cli id-policy get > id-policy.json
sakura-iam-cli id-policy update id-policy.json --dry-run
sakura-iam-cli id-policy update id-policy.json
```

入力JSONの形式:

```json
{
  "bindings": [
    {
      "role": {"type": "preset", "id": "identity-admin"},
      "principals": [
        {"type": "user", "id": 111111111111},
        {"type": "group", "id": 1},
        {"type": "service-principal", "id": 222222222222}
      ]
    }
  ]
}
```

## 組織とサービスポリシー

組織情報を参照し、組織名を更新します。

```console
sakura-iam-cli organization get
sakura-iam-cli organization update --name "新しい組織名" --dry-run
sakura-iam-cli organization update --name "新しい組織名"
```

サービスポリシーの状態と利用可能なルールテンプレートを確認し、有効化または無効化します。

```console
sakura-iam-cli service-policy status
sakura-iam-cli service-policy templates --per-page 100
sakura-iam-cli service-policy enable --dry-run
sakura-iam-cli service-policy enable
sakura-iam-cli service-policy disable --dry-run
```

設定済みルールを取得し、JSONファイルで指定したルールを更新します。`--rules-dry-run`はAPI上でドライラン状態のルールを絞り込むオプションです。`update --dry-run`はローカル検証だけを行い、APIへ送信しません。

```console
sakura-iam-cli service-policy list > service-policy.json
sakura-iam-cli service-policy list --active --type list
sakura-iam-cli service-policy update service-policy.json --dry-run
sakura-iam-cli service-policy update service-policy.json
```

更新ファイルの`rules`には更新対象だけを指定できます。`service-policy list`の出力をそのまま編集した場合、参照専用の`name`は送信時に自動的に除外されます。

```json
{
  "rules": [
    {
      "code": "cloud-restrict-zone",
      "spec": {
        "contents": [
          {
            "allow_all": false,
            "deny_all": false,
            "values": {"allowed_values": ["is:is1a"]}
          }
        ]
      },
      "is_active": true,
      "is_dry_run": false
    }
  ]
}
```

## 認証設定

現在のサービスプリンシパルの認証種別、リソースID、操作可能なプロジェクトIDを確認します。

```console
sakura-iam-cli auth context
```

組織のパスワードポリシーを取得し、JSONファイルで更新します。

```console
sakura-iam-cli auth password-policy > password-policy.json
sakura-iam-cli auth update-password-policy password-policy.json --dry-run
sakura-iam-cli auth update-password-policy password-policy.json
```

```json
{
  "min_length": 12,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_symbols": true
}
```

送信元IPv4ネットワーク、2要素認証必須化、ログイン可能期間を含む認証条件を取得・更新します。

```console
sakura-iam-cli auth conditions > auth-conditions.json
sakura-iam-cli auth update-conditions auth-conditions.json --dry-run
sakura-iam-cli auth update-conditions auth-conditions.json
```

```json
{
  "ip_restriction": {
    "mode": "allow_list",
    "source_network": ["192.0.2.0/24"]
  },
  "require_two_factor_auth": {"enabled": true},
  "datetime_restriction": {
    "after": null,
    "before": null
  }
}
```

認証条件を誤ると管理者自身がログインできなくなる可能性があります。更新前に取得結果を保存し、`--dry-run`で入力を検証してください。

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

## リソースツリーをls/mv形式で操作

`resource`では、フォルダとプロジェクトを同じツリーとして扱えます。パスは`/`から始まる絶対パスです。

```console
# ルートとフォルダ直下を表示
sakura-iam-cli resource ls /
sakura-iam-cli resource ls /Production

# JSON形式で表示
sakura-iam-cli resource ls /Production --json

# フォルダをパスで作成
sakura-iam-cli resource mkdir /Production/Batch
sakura-iam-cli resource mkdir -p /Production/Apps/Batch/Logs

# プロジェクトまたはフォルダを移動（末尾が移動先）
sakura-iam-cli resource mv /Development/automation-project /Production/
sakura-iam-cli resource mv /Development/Batch /Production/

# 複数リソースを移動
sakura-iam-cli resource mv \
  /Development/project-a \
  /Development/project-b \
  /Production/

# ルートへ移動
sakura-iam-cli resource mv /Production/OldProject /
```

プロジェクトは名前とプロジェクトコードのどちらでも解決できます。同じ階層に同名候補があり曖昧な場合、CLIは処理を中止するためID形式で指定してください。

```console
sakura-iam-cli resource mv project:123456789012 folder:223000000000
sakura-iam-cli resource mv folder:224000000000 /
```

事前確認には`--dry-run`を使います。パス解決のため一覧APIと認証は実行しますが、移動APIは呼び出しません。

```console
sakura-iam-cli resource mv /Development/Batch /Production/ --dry-run
```

フォルダを自身や子孫へ移動する操作は事前に拒否されます。フォルダとプロジェクトを同時に指定した移動はAPI上では別々のリクエストになるため、完全な原子操作ではありません。既存の`folder move`と`project move`はIDを直接扱う低レベルコマンドとして引き続き利用できます。

`resource mkdir`は通常、親フォルダが存在する場合だけ末尾のフォルダを作成します。`--parents`または`-p`を指定すると不足している親フォルダも作成し、対象パスがすでに存在する場合は成功扱いで何もしません。`--description`は最後に作るフォルダにだけ設定されます。`--dry-run`ではパス解決用の一覧APIだけを呼び出します。

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

## ユーザープロビジョニング

外部IdPからユーザとグループを同期するSCIMユーザープロビジョニング設定を管理します。

```console
sakura-iam-cli provisioning list
sakura-iam-cli provisioning create --name "Microsoft Entra ID" \
  --output provisioning-credentials.json
sakura-iam-cli provisioning get 550e8400-e29b-41d4-a716-446655440000
sakura-iam-cli provisioning update 550e8400-e29b-41d4-a716-446655440000 \
  --name "Microsoft Entra ID Production"
sakura-iam-cli provisioning regenerate-token \
  550e8400-e29b-41d4-a716-446655440000 \
  --output regenerated-token.json --dry-run
sakura-iam-cli provisioning delete \
  550e8400-e29b-41d4-a716-446655440000 --dry-run
```

作成時に返るBase URLとシークレットトークンをIdPへ設定します。シークレットを含む応答は一度しか取得できないため、`--output`を指定すると新規ファイルへ`0600`で保存します。既存ファイルは上書きしません。トークン再発行は以前のトークンを即座に無効化するため、まず`--dry-run`で対象IDを確認してください。

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

削除、無効化、移動、所属ユーザの置換などの対応コマンドでは`--dry-run`を利用できます。通常のdry-runでは認証やIAM API呼び出し、ローカルJSONの更新を行いません。`resource mv --dry-run`のみ、パス解決に必要な一覧取得と認証を行いますが、変更APIは呼び出しません。

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
