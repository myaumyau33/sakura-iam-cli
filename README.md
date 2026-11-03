# sakura-iam-cli

さくらのクラウドのIAMを、サービスプリンシパル認証で操作する非公式CLIです。

## できること

| 機能                       | 主な操作                                                                                                | コマンド                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------- |
| 設定・プロファイル管理     | 対話形式の初回設定、プロファイル追加・編集・一覧、既定プロファイルの切り替え                              | `config`                  |
| プロジェクト・フォルダ管理 | 一覧、取得、作成、更新、削除、移動                                                                      | `project` / `folder`      |
| パスによるリソース操作     | `ls`で一覧表示、`tree`で階層表示、`mkdir -p`で階層作成、`mv`で一括移動                                    | `resource`                |
| サービスプリンシパル管理   | 一覧、取得、作成、更新、削除、アクセストークン取得、IAM・IDロールの割り当て診断                          | `sp`                      |
| 認証用の鍵管理             | RSA鍵の一括生成、公開鍵の一括登録、登録済み鍵の一覧・有効化・無効化・削除                               | `sp-key`                  |
| プロジェクトAPIキー管理    | 一覧、取得、作成、更新、削除、作成したキーでの認証確認                                                  | `api-key`                 |
| IAMロール・ポリシー管理    | ロール参照、組織・フォルダ・プロジェクトのポリシー取得・更新、対話形式での権限追加・削除                | `iam-role` / `iam-policy` |
| IDロール・ポリシー管理     | ロール参照、組織IDポリシーの取得・更新                                                                  | `id-role` / `id-policy`   |
| ユーザ管理                 | 一覧、取得、作成、更新、削除、メール登録・解除、OTP解除、信頼済みデバイス・セキュリティキーの参照・削除 | `user`                    |
| グループ管理               | 一覧、取得、作成、更新、削除、所属ユーザの参照・置換                                                    | `group`                   |
| SCIM連携管理               | プロビジョニング設定の一覧、取得、作成、更新、削除、トークン再発行                                      | `provisioning`            |
| 組織管理                   | 組織情報の取得、組織名の更新                                                                            | `organization`            |
| サービスポリシー管理       | 状態確認、有効化・無効化、ルールテンプレート参照、ルール取得・更新                                      | `service-policy`          |
| 認証設定管理               | 認証コンテキストの確認、パスワードポリシー・IP制限・2要素認証必須化・ログイン可能期間の取得・更新       | `auth`                    |
| 任意のURLへのリクエスト     | SPトークンまたはAPIキーを使ったHTTPリクエスト、ボディ・ヘッダーの指定                                    | `raw-url` / `api-key raw-url` |

複数プロファイルの切り替え、JSON出力、シェル補完、対応コマンドでの`--dry-run`による事前確認も利用できます。引数やオプションは各コマンドの`--help`で確認してください。

## インストールと初期設定

Python 3.12以上と[uv](https://docs.astral.sh/uv/)が必要です。認証用サービスプリンシパルと登録済みの鍵を用意してから、リポジトリのルートで実行します。

```console
uv tool install .
sakura-iam-cli config init
sakura-iam-cli auth context
```

`config init`でSP ID・登録済みの鍵のkid・秘密鍵ファイルのパスを入力すると、`settings.json`を権限`0600`で作成します。既存ファイルは上書きしません。秘密鍵の相対パスは実行ディレクトリを基準に解決し、絶対パスで保存します。

秘密鍵も所有者だけが読める権限（`0600`または`0400`）にしてください。保存前にRSA秘密鍵として読み込めるか確認します。設定操作ではAPIを呼ばず、接続確認は`auth context`で行います。秘密鍵やシークレットをGitに登録しないでください。

ユーザ・グループの管理にはIDロール、それ以外のリソース操作には対象に応じたIAMロールが必要です。既存プロジェクトの権限だけでは、ユーザ管理や別の階層での操作ができない場合があります。

## プロファイルの管理

```console
sakura-iam-cli config add production
sakura-iam-cli config edit production
sakura-iam-cli config list
sakura-iam-cli config use production
```

`add`は新しいプロファイルを対話入力で追加します。`edit`は現在値を初期値として編集し、名前を省略すると既定のプロファイルを使います。`use`は以後の既定プロファイルを切り替えます。追加時に`--default`を付けることもできます。

オプションで値を直接指定することもできます。`edit`でオプションを指定した場合は対話入力せず、指定項目を更新します。

```console
sakura-iam-cli config edit production --kid NEW_KID
sakura-iam-cli config edit production --project-id 123456789012
sakura-iam-cli config edit production --project-id -
sakura-iam-cli --settings ~/.config/sakura-iam/settings.json config init
```

`project_id`は認証には不要で、`sp create`・`api-key create`の作成先の既定値です。`-`で解除できます。`--base-url`でIAM APIの接続先を指定でき、`-`で標準URLに戻せます。初回設定・追加も`--service-principal-id`・`--kid`・`--private-key`をすべて指定すれば対話入力を省略できます。

## 基本の使い方

```console
sakura-iam-cli [--settings 設定ファイル] [--profile プロファイル名] コマンド
```

設定ファイルの既定値は実行ディレクトリの`settings.json`です。共通オプションはサブコマンドの前に指定します。

```console
sakura-iam-cli --settings ~/.config/sakura-iam/settings.json --profile production project list
sakura-iam-cli --help
sakura-iam-cli project --help
sakura-iam-cli project create --help
```

通常の結果はJSONで出力します。ページ指定に対応する一覧コマンドでは、`--page`と`--per-page`で取得範囲を指定できます。全件が必要な場合は続きのページも取得してください。

```console
sakura-iam-cli project list --page 1 --per-page 100
sakura-iam-cli project get 123456789012 > project.json
```

インストールせずに使う場合は、リポジトリ内で`uv sync`を実行し、各例の`sakura-iam-cli`を`uv run sakura-iam-cli`に置き換えてください。

## よく使う操作

### 任意のURLを呼び出す

`raw-url METHOD URL`で、用意されたコマンド以外のAPIも呼び出せます。選択したプロファイルで取得したSPトークンを、指定したURLへ`Authorization: Bearer ...`として送信します。

```console
sakura-iam-cli raw-url POST https://iam.example.com/status
sakura-iam-cli --profile production raw-url GET 'https://iam.example.com/status?detail=true'
sakura-iam-cli raw-url POST https://iam.example.com/status --json '{"enabled":true}'
sakura-iam-cli raw-url PATCH https://iam.example.com/status --json @request.json
sakura-iam-cli raw-url PUT https://iam.example.com/status --data @payload.bin -H 'Content-Type: application/octet-stream'
```

APIキーで呼び出す場合は`api-key raw-url METHOD URL --credentials ファイル`を使います。`api-key create --output`で保存したJSON（`access_token`と`access_token_secret`）を指定してください。ファイルの権限は`0600`にします。SPの設定やトークンは使わず、APIキーでBasic認証します。

```console
sakura-iam-cli api-key raw-url GET https://secure.sakura.ad.jp/cloud/zone/is1a/api/cloud/1.1/auth-status --credentials ./work/api-key.json
sakura-iam-cli api-key raw-url POST https://api.example.com/status --credentials ./work/api-key.json --json @request.json
```

両コマンドで次のオプションと出力形式を使えます。

`--json`はJSONを検証し、`Content-Type: application/json`を設定します。`--data`は内容をそのまま送信します。どちらも文字列、`@ファイルパス`、標準入力を表す`-`を指定でき、同時には使えません。追加ヘッダーは`-H '名前: 値'`で繰り返し指定できます。`Authorization`は自動設定されます。

応答ボディは加工せず標準出力へ出すので、ファイル保存やパイプに使えます。HTTPエラー時はサーバーが返した本文だけを、そのまま標準エラーへ出します。`error:`などの接頭辞や改行は追加せず、終了コードは非ゼロになります。URLはHTTPSを使ってください（ローカルのloopback宛てはHTTPも可）。リダイレクトには追従しません。

### プロジェクトとフォルダ

```console
sakura-iam-cli project list
sakura-iam-cli folder create --name Production
sakura-iam-cli project create --code batch --name "Batch Project" --parent-folder-id 112000000000
sakura-iam-cli project move --project-id 123456789012 --parent-folder-id 112000000000 --dry-run
sakura-iam-cli project delete 123456789012 --dry-run
```

パスで操作する場合は`resource`を使います。パスは`/`から始め、`mv`の最後の引数に移動先フォルダを指定します。

```console
sakura-iam-cli resource ls /
sakura-iam-cli resource ls /Production --json
sakura-iam-cli resource tree
sakura-iam-cli resource tree /Production --depth 2
sakura-iam-cli resource tree folder:112000000000 --json
sakura-iam-cli resource mkdir -p /Production/Apps/Batch
sakura-iam-cli resource mv /Development/batch /Production/ --dry-run
sakura-iam-cli resource mv project:123456789012 folder:112000000000 --dry-run
```

プロジェクトは名前またはコードで指定できます。同名の候補がある場合は`project:ID`や`folder:ID`を使ってください。`mkdir -p`は不足している親フォルダも作成します。

`resource tree`はフォルダとプロジェクトを再帰的に表示します。対象は省略すると`/`で、フォルダの絶対パスまたは`folder:ID`を指定できます。名前・プロジェクトコード・IDを表示するため、後続の操作にも使えます。

```text
/
└── Production/ (folder:112000000000)
    └── Batch Project [batch] (project:123456789012)
```

`--depth N`（短縮形`-L N`）で表示階層を制限できます。`1`は対象フォルダの直下だけを表示します。`--json`はフォルダごとの`children`を含む階層JSONを出力します。

### IAMロールの割り当て

ユーザやサービスプリンシパルへの割り当てを対話形式で追加・削除できます。

```console
sakura-iam-cli iam-policy add
sakura-iam-cli iam-policy add --project-id 123456789012 --dry-run
sakura-iam-cli iam-policy delete --project-id 123456789012 --dry-run
```

対象・プリンシパル・ロールを選択します。上下キーで移動、Spaceで選択、Enterで確定します。`add`は既存の割り当てを保持し、チェックを外しても削除しません。削除は`delete`で行います。

JSONで管理する場合は、現在のポリシーを保存して編集し、更新します。対象には`--organization`、`--folder-id`、`--project-id`のいずれか1つを指定します。

```console
sakura-iam-cli iam-policy get --project-id 123456789012 > iam-policy.json
# iam-policy.jsonを編集
sakura-iam-cli iam-policy update iam-policy.json --project-id 123456789012 --dry-run
sakura-iam-cli iam-policy update iam-policy.json --project-id 123456789012
```

`update`は対象階層のポリシー全体を置き換えます。空の`bindings`を指定すると、その階層の直接の割り当てをすべて解除します。上位から継承した権限は変更しません。

### プロジェクトAPIキー

```console
sakura-iam-cli iam-role list --per-page 100
sakura-iam-cli api-key create --project-id 123456789012 --name automation --iam-role resource-viewer --output ./work/api-key.json
sakura-iam-cli api-key auth-status ./work/api-key.json --zone is1a
sakura-iam-cli api-key list
```

ロールは`iam-role list`が返すIDで指定し、複数の場合は`--iam-role`を繰り返します。作成先は`--project-id`で指定します。シングルサーバ用は`--server-resource-id`と`--zone-id`を両方指定します。

シークレットは作成時にだけ取得できます。`--output`を指定すると応答を権限`0600`の新規ファイルへ保存し、既存ファイルは上書きしません。省略するとシークレットを含む応答を標準出力へ表示します。

### サービスプリンシパルと鍵

IAM・IDポリシーを調べるには`sp check-permissions`を使います。対象SPのIDを省略すると認証中のSPを調べ、IAMの対象を省略するとそのSPの所属プロジェクトを使います。

```console
sakura-iam-cli sp check-permissions
sakura-iam-cli sp check-permissions --project-id 123456789012 --iam-role owner --id-role identity-admin
sakura-iam-cli sp check-permissions --folder-id 112000000000 --iam-role project-creator --json
sakura-iam-cli --profile admin sp check-permissions 987654321098 --project-id 123456789012 --id-role identity-admin
```

IAMは対象と親フォルダ・組織のポリシー、IDは組織IDポリシーを参照し、対象SPのロールと付与元を表示します。`--project-id`・`--folder-id`・`--organization`は同時に指定できません。必要なロールは`--iam-role`・`--id-role`で繰り返し指定できます。指定しない場合は割り当て一覧と参照可否を表示します。

指定ロールは「あり／未割当／判定不能」で表示します。ポリシー参照の拒否・通信失敗・不完全な応答は「判定不能」にし、「未割当」と区別します。参照権限が足りない場合は、管理用プロファイルで対象SPのIDを指定して再確認してください。診断では参照APIだけを呼び、設定を変更しません。

ロールはIDの完全一致で確認します。別ロールによる同等権限、サービスポリシーやAPI固有の制約は評価しないため、操作の実行可否を保証するものではありません。終了コードは、指定ロールが確認できた場合（指定なしなら調査完了）が`0`、未割当が`1`、判定不能が`2`です。複数指定時は未割当の`1`を優先します。`--json`には判定理由と各ポリシーの参照結果も含みます。

仕様の詳細: [IAMポリシーの継承](https://manual.sakura.ad.jp/cloud/controlpanel/iam-policy.html)、[IDポリシー](https://manual.sakura.ad.jp/cloud/controlpanel/id-policy.html)。

```console
sakura-iam-cli sp list
sakura-iam-cli sp create --project-id 123456789012 --name batch-worker
sakura-iam-cli sp-key create --num 10 --output-key-dir ./work/keys
sakura-iam-cli sp-key upload-key --service-principal-id 987654321098 --key-dir ./work/keys
sakura-iam-cli sp-key list --service-principal-id 987654321098
sakura-iam-cli sp-key disable --key-dir ./work/keys --dry-run
sakura-iam-cli sp-key delete --key-dir ./work/keys --dry-run
```

`sp-key create`はローカルで鍵を生成し、`upload-key`は既存の認証設定を使って公開鍵を登録します。登録先は認証用サービスプリンシパルと別でも構いません。

登録結果は鍵と同じディレクトリの`*.public.json`に保存します。`disable`・`enable`・`delete`はこの記録にある鍵を一括操作するため、記録を保管してください。リモートの鍵を削除してもローカルの鍵は残ります。

### ユーザとグループ

```console
sakura-iam-cli user list
sakura-iam-cli user create --name Operator --code operator
sakura-iam-cli group create --name Operators
sakura-iam-cli group members 1
sakura-iam-cli group set-members 1 --user-id 111111111111 --user-id 222222222222 --dry-run
```

ユーザ作成時のパスワードは非表示で対話入力します。ファイルから読む場合は`--password-file`を指定します。`group set-members`は所属ユーザ全体を置き換えます。全員を外す場合は`--clear`を指定してください。

メール・OTP・信頼済みデバイス・セキュリティキーの操作は`sakura-iam-cli user --help`で確認できます。

### 組織の設定とSCIM連携

ポリシーや認証設定は取得したJSONを編集して更新します。

```console
sakura-iam-cli id-role list
sakura-iam-cli id-policy get > id-policy.json
sakura-iam-cli id-policy update id-policy.json --dry-run
sakura-iam-cli auth password-policy > password-policy.json
sakura-iam-cli auth update-password-policy password-policy.json --dry-run
sakura-iam-cli auth conditions > auth-conditions.json
sakura-iam-cli auth update-conditions auth-conditions.json --dry-run
sakura-iam-cli service-policy list > service-policy.json
sakura-iam-cli service-policy update service-policy.json --dry-run
```

`id-policy update`もポリシー全体を置き換えます。認証条件の変更はログイン可否に影響するため、現在の設定を保存してから編集してください。

SCIM連携の作成では、接続先URLとトークンを保存してIdPへ設定します。

```console
sakura-iam-cli provisioning create --name "Microsoft Entra ID" --output ./work/provisioning.json
sakura-iam-cli provisioning list
```

トークンを含む応答は`--output`で権限`0600`の新規ファイルに保存できます。`regenerate-token`は以前のトークンを即座に無効化します。

## 変更前の確認

対応するコマンドに`--dry-run`を付けると、変更せずに対象や入力を確認できます。実行するには内容を確認したうえで`--dry-run`を外します。

```console
sakura-iam-cli folder delete 112000000000 --dry-run
```

`--dry-run`はAPI側の権限や実行成功を保証しません。`resource mv`・`resource mkdir`と`iam-policy add`・`iam-policy delete`は、dry-runでも認証・参照APIを呼び出します。

## シェル補完と更新

インストールしたCLIで補完を設定します。設定後にシェルを再起動してください。

```console
sakura-iam-cli --install-completion
```

コマンドが見つからない場合は`uv tool update-shell`でPATHを設定し、シェルを再起動してください。ソースの更新後は、リポジトリのルートで再インストールします。

```console
uv tool install --force --reinstall .
```

API・認証の詳細: [IAM API](https://manual.sakura.ad.jp/api/cloud/portal/?api=iam-api)、[サービスプリンシパル](https://manual.sakura.ad.jp/cloud/controlpanel/service-principal.html#id8)
