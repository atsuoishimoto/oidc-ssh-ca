
# oidc-ssh-ca 企画書 (v4)

## 1. 概要

`oidc-ssh-ca` は、OIDC / JWT / IAM などで認証された実行主体に対して、短命の OpenSSH user certificate を発行する軽量な SSH CA です。

主な対象は、個人開発者、小規模チーム、小規模企業です。

目的は、GitHub Actions などの CI/CD や簡易運用ワークフローから、長期 SSH 秘密鍵を GitHub Secrets などに置かずに、安全に SSH / Ansible / rsync / shell script を実行できるようにすることです。

このツールは、大規模な認証基盤を置き換えるものではありません。Vault / OpenBao / Teleport のような高機能な基盤を導入するほどではないが、長期 SSH 鍵の配布や GitHub Secrets への保存を避けたい場面に向けた、小さな SSH certificate issuer です。

実装言語は Go とします。理由:

```text
golang.org/x/crypto/ssh で SSH 証明書の署名・検証・パースが
標準的なライブラリとして完結する
  → ssh-keygen subprocess が不要
  → CA 秘密鍵をディスクに書かずメモリ内だけで署名できる

single static binary として配布できる
  → コンテナが必須でなくなる
  → VPS には binary + systemd unit だけで導入できる
  → Lambda には zip (provided.al2023) でデプロイできる
  → openssh-client 等のランタイム依存がゼロになる

一時ファイル管理 / subprocess timeout / 引数注入の
考慮事項が設計から丸ごと消える
```

---

## 2. 企画の一文

`oidc-ssh-ca` は、GitHub Actions などの OIDC/JWT identity から短命 OpenSSH user certificate を発行する、小規模運用向けの軽量 SSH CA です。single static binary として動作し、GitHub Secrets に長期 SSH 秘密鍵を置かず、既存の `ssh` / Ansible / `rsync` / shell script をそのまま使えるようにします。

---

## 3. 解決したい課題

従来の小規模 SSH 運用では、次のような問題が起きがちです。

```text
GitHub Secrets に長期 SSH 秘密鍵を置く
各サーバに authorized_keys を配る
鍵ローテーションが面倒
repo / branch / workflow 単位で権限を切りにくい
漏洩時に全サーバの authorized_keys を掃除する必要がある
```

`oidc-ssh-ca` はこれを次の形に置き換えます。

```text
GitHub Actions が一時 SSH 鍵を生成
OIDC / JWT / IAM で実行主体を証明
oidc-ssh-ca が短命 SSH certificate を発行
サーバは CA 公開鍵だけを信頼
```

---

## 4. 想定ユースケース

### 4.1 GitHub Actions からのデプロイ

```text
GitHub Actions
  ↓ OIDC JWT
oidc-ssh-ca
  ↓ 短命 SSH certificate
ssh / ansible / rsync
  ↓
対象サーバ
```

GitHub Actions 側では、毎回一時 SSH 鍵を生成し、その公開鍵だけを `oidc-ssh-ca` に送ります。`oidc-ssh-ca` は OIDC/JWT の claim を検証し、設定ファイルのルールに合えば短命 SSH 証明書を発行します。

### 4.2 簡易運用ツール

GitHub Actions の `workflow_dispatch` を使い、GitHub UI から運用操作を実行します。

例:

```text
restart
status
deploy
rollback
tail-log
backup
maintenance on/off
```

GitHub Actions は実行 UI、履歴、ログ、承認フローとして使い、実際の操作は SSH certificate を使った SSH / shell script で行います。

### 4.3 Ansible 実行

既存の SSH inventory を活かしつつ、長期秘密鍵ではなく短命証明書で接続します。

```bash
ansible-playbook -i inventory.ini site.yml \
  --private-key ./gha_key \
  -u deploy \
  --ssh-common-args="-o CertificateFile=./gha_key-cert.pub -o IdentitiesOnly=yes"
```

### 4.4 rsync / scp / shell script

OpenSSH certificate を使うため、Ansible だけでなく通常の SSH 周辺ツールも利用できます。

```bash
rsync -e "ssh -i gha_key -o CertificateFile=gha_key-cert.pub -o IdentitiesOnly=yes" \
  ./dist/ deploy@example.com:/var/www/app/
```

---

## 5. 基本コンセプト

### 5.1 秘密鍵を配らない

GitHub Actions 側で毎回一時 SSH 鍵を生成します。

```bash
ssh-keygen -t ed25519 -N "" -f gha_key
```

`oidc-ssh-ca` に送るのは公開鍵だけです。

```json
{
  "public_key": "ssh-ed25519 AAAA..."
}
```

CA サーバは秘密鍵を生成しません。秘密鍵をネットワーク越しに返すこともしません。

### 5.2 短命 SSH 証明書を発行する

`oidc-ssh-ca` は、検証済み identity に対して、数分〜十数分だけ有効な SSH user certificate を発行します。

例:

```text
principal: gha-prod-deploy
valid: now - 30s 〜 now + 10m
```

### 5.3 サーバ側は OpenSSH 標準機能だけを使う

対象サーバ側では、信頼する CA 公開鍵を置きます。

```sshconfig
TrustedUserCAKeys /etc/ssh/oidc-ssh-ca.pub

Match User deploy
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

`/etc/ssh/auth_principals/deploy`:

```text
gha-prod-deploy
```

sshd は次を検証します。

```text
証明書が信頼済み CA で署名されているか
証明書が有効期限内か
証明書の principal がログイン先ユーザーに許可されているか
```

### 5.4 接続先も検証する (host key)

user 認証を短命証明書に置き換えても、接続先サーバの検証 (host key 検証) を省略すると MITM に対して片手落ちになります。本プロジェクトでは次を標準の推奨とします。

```text
MVP:
  pinned known_hosts をリポジトリにコミットし、
  StrictHostKeyChecking=yes で接続する

発展 (Phase 4):
  同じ CA で host certificate も発行し、
  クライアント側は known_hosts に @cert-authority 1 行を書くだけにする
```

GitHub Actions example (16章) には known_hosts の固定手順を必ず含めます。

### 5.5 CA 秘密鍵をディスクに書かない

Go + `golang.org/x/crypto/ssh` によるインメモリ署名を採用するため、CA 秘密鍵は次のように扱えます。

```text
mount / Secrets Manager / SSM から取得
  ↓
メモリ上で parse (ssh.ParsePrivateKey)
  ↓
メモリ上で署名 (Certificate.SignCert)
  ↓
ディスクには一度も書かない
```

一時ファイル・subprocess・外部コマンド依存が存在しないことを、設計上の保証として README に明記します。

---

## 6. 基本アーキテクチャ

### 6.1 GitHub Actions OIDC direct mode

```text
GitHub Actions
  ↓ GitHub OIDC JWT
oidc-ssh-ca /sign
  ↓ JWT 検証
  ↓ policy.yaml 照合
  ↓ OpenSSH user certificate 発行 (インメモリ署名)
GitHub Actions
  ↓ ssh / ansible
対象サーバ
```

### 6.2 スタンドアローン運用

個人 VPS や小規模インフラ向けです。single static binary なので、コンテナは必須ではありません。

最小構成 (binary + systemd):

```text
/usr/local/bin/oidc-ssh-ca
/etc/oidc-ssh-ca/policy.yaml
/etc/oidc-ssh-ca/ca_key          (mode 0600, 専用ユーザー所有)
systemd unit (DynamicUser / ProtectSystem などで隔離)
```

systemd unit 例:

```ini
[Service]
ExecStart=/usr/local/bin/oidc-ssh-ca serve --config /etc/oidc-ssh-ca/policy.yaml
DynamicUser=yes
LoadCredential=ca_key:/etc/oidc-ssh-ca/ca_key
Environment=OIDC_SSH_CA_KEY_FILE=%d/ca_key
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
```

`LoadCredential` を使うことで、CA 鍵はサービス専用の credential として渡されます。`%d` は credential ディレクトリに展開されるため、`OIDC_SSH_CA_KEY_FILE` で通常のファイルパスとしてそのまま指定できます (鍵の設定方法は 12.4 参照)。

コンテナでの運用も引き続きサポートします (6.4)。

### 6.3 Lambda / サーバレス運用

低頻度の運用用途向けです。Go は AWS Lambda の `provided.al2023` ランタイムで動くため、**コンテナイメージは不要**で、binary を zip にしてデプロイできます。

```text
GitHub Actions / Terraform
  ↓ zip (bootstrap binary)
Lambda (provided.al2023) + Function URL
  ↓
Secrets Manager / SSM / CloudWatch
```

ECR リポジトリの管理・イメージのビルドとプッシュが不要になり、AWS デプロイの構成要素が「zip + 関数 + ロール」まで減ります。コールドスタートも Go zip はコンテナイメージより速い傾向があります。

AWS 固有機能は初期の中核機能ではなく、後述の発展機能として扱います。

### 6.4 デプロイ形態まとめ

```text
binary + systemd     : VPS / オンプレの推奨。依存ゼロ
Lambda zip           : AWS サーバレスの推奨。ECR 不要
Docker (scratch 系)  : Cloud Run / Fly.io / ECS / k8s 向けの利便提供
```

---

## 7. API 仕様案

### 7.1 `POST /sign`

認証済み identity に対して SSH certificate を発行します。

#### リクエスト

```http
POST /sign
Authorization: Bearer <OIDC_JWT>
Content-Type: application/json
```

```json
{
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
}
```

#### レスポンス

成功時は OpenSSH certificate public key を text/plain で返します。

```text
ssh-ed25519-cert-v01@openssh.com AAAA... gha:your-org/your-repo:123456789:1
```

#### 重要な方針

リクエスト body から以下は受け取りません。

```text
principal
repository
ref
workflow
environment
TTL
extensions
```

これらは、検証済み JWT claim と `policy.yaml` から決定します。

#### エラーレスポンス方針

エラーレスポンスに内部詳細を含めません。

```text
スタックトレース / ファイルパス / 内部エラー文字列を返さない
拒否理由は固定の汎用メッセージ + リクエスト ID のみ
詳細はサーバ側の監査ログにだけ残す
```

caller には「リクエスト ID を添えて管理者に問い合わせる」導線を示し、デバッグは管理者がログで行います。拒否理由を詳細に返すことは、policy の探索 (どの claim を変えれば通るかの試行) を助けてしまうため行いません。

---

## 8. 設定ファイル方針

設定ファイルは YAML を標準とします。

理由:

```text
階層構造を自然に表現できる
GitHub Actions / Ansible ユーザーに馴染みがある
rules[].match.certificate の構造が読みやすい
コメントを書ける
設定例が README に載せやすい
```

一方で YAML には型解釈の曖昧さがあるため、実装側では厳密な schema validation を行います。

方針:

```text
未知の field はエラー (yaml.Decoder の KnownFields(true) を使用)
型違いはエラー
必須 field の不足はエラー
defaults 適用後の最終設定を check-config で確認可能にする
```

---

## 9. policy.yaml 例

### 9.1 GitHub Actions OIDC direct mode

```yaml
version: 1

# 緊急停止フラグ (true で全発行を停止)
disabled: false

defaults:
  valid_after_offset_seconds: -30
  max_valid_for_seconds: 900
  allowed_public_key_types:
    - "ssh-ed25519"

  extensions:
    permit_pty: false
    permit_port_forwarding: false
    permit_agent_forwarding: false
    permit_x11_forwarding: false
    permit_user_rc: false

rules:
  - name: "prod-deploy"
    enabled: true

    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-prod"
        claims_exact:
          repository: "your-org/your-repo"
          ref: "refs/heads/main"
          environment: "production"
          event_name: "push"
          job_workflow_ref: "your-org/your-repo/.github/workflows/deploy.yml@refs/heads/main"

    certificate:
      principals:
        - "gha-prod-deploy"
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
```

### 9.2 staging ルールを追加する例

```yaml
rules:
  - name: "prod-deploy"
    enabled: true
    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-prod"
        claims_exact:
          repository: "your-org/your-repo"
          ref: "refs/heads/main"
          environment: "production"
          event_name: "push"
          job_workflow_ref: "your-org/your-repo/.github/workflows/deploy.yml@refs/heads/main"
    certificate:
      principals: ["gha-prod-deploy"]
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"

  - name: "staging-deploy"
    enabled: true
    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-staging"
        claims_exact:
          repository: "your-org/your-repo"
          ref: "refs/heads/develop"
          environment: "staging"
          event_name: "push"
          job_workflow_ref: "your-org/your-repo/.github/workflows/deploy.yml@refs/heads/develop"
    certificate:
      principals: ["gha-staging-deploy"]
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
```

### 9.3 claim の存在条件について

`claims_exact` に書ける claim には、workflow の書き方によって**そもそも JWT に含まれない**ものがあります。代表例:

```text
environment:
  workflow の job が environment: を指定した場合のみ含まれる

job_workflow_ref:
  reusable workflow を使うと、呼び出し先 workflow の参照になる
  (呼び出し元と異なる値になることに注意)

ref:
  pull_request イベントでは merge ref になるなど、
  イベント種別で値の形が変わる
```

policy で参照した claim が JWT に存在しない場合は match 不成立 (deny) です。これは安全側ですが、利用者がハマりやすいため、`docs/policy.md` に「各 claim が出る条件」を一覧化し、`explain` コマンドで実際の claim を確認できるようにします。

---

## 10. ルール設計

### 10.1 match

`match` は、検証済み identity の条件を表します。

初期版では exact match 中心にします。

```yaml
match:
  jwt:
    issuer: "https://token.actions.githubusercontent.com"
    audience: "ssh-ca-prod"
    claims_exact:
      repository: "your-org/your-repo"
      ref: "refs/heads/main"
      environment: "production"
```

将来的に追加できる条件:

```yaml
match:
  jwt:
    claims_one_of:
      ref:
        - "refs/heads/main"
        - "refs/heads/release"

    claims_glob:
      ref: "refs/tags/v*"
```

### 10.2 certificate

`certificate` は、マッチ時に発行する SSH 証明書の内容を表します。

```yaml
certificate:
  principals:
    - "gha-prod-deploy"
  valid_for_seconds: 600
  key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
  extensions:
    permit_pty: false
    permit_port_forwarding: false
    permit_agent_forwarding: false
    permit_x11_forwarding: false
```

principal はリクエスト body から受け取りません。必ず policy の rule から決定します。

### 10.3 key_id_template のサニタイズ仕様

`key_id_template` は claim 値を展開しますが、claim 値は caller がある程度制御できる文字列です。Key ID は sshd のログにそのまま出力されるため、無制限な値の埋め込みはログ注入の問題につながります。

仕様:

```text
テンプレートに展開できるのは検証済み JWT claim (または AWS caller 情報) のみ

展開後の各値は許可文字のみで構成されていなければならない:
  [A-Za-z0-9 . _ / : @ -]

許可外の文字 (改行・空白・引用符・制御文字など) を含む場合:
  置換や除去はせず、リクエスト全体を deny する
  (監査値を黙って改変しない)

展開後の Key ID 全体の長さ上限: 256 bytes
超過時は deny
```

`check-config` は、テンプレートが参照する claim 名が既知の claim 一覧に含まれるかを警告します。

---

## 11. 安全なデフォルト

初期版では以下をデフォルトにします。

```text
公開鍵は ssh-ed25519 のみ許可
証明書 TTL に上限を設ける
複数 rule にマッチしたら deny
rule にマッチしなければ deny
policy が読めなければ起動失敗 / deny
CA 鍵が読めなければ deny
principal は request body から受け取らない
証明書 extensions は原則無効
エラーレスポンスに内部詳細を含めない
key_id 展開値は許可文字制限、違反は deny
```

特に重要なのは、複数マッチ時の扱いです。

```text
0件 match:
  deny

1件 match:
  issue certificate

2件以上 match:
  deny
```

「上から最初にマッチ」方式は便利ですが、設定ミスで意図しない広いルールが使われる危険があります。初期版では exactly one match が安全です。

### 11.1 policy のリロードと緊急停止 (MVP に含む)

緊急時に「発行を止める」操作は運用初日から必要になり得るため、MVP の仕様として定めます。

リロード方針:

```text
スタンドアローン:
  起動時に policy を読み込み、読めなければ起動失敗
  SIGHUP で再読み込み
  再読み込みした policy が invalid な場合:
    旧 policy を維持して稼働を続け、error ログを出す
    (リロード失敗で発行が止まる/緩む、のどちらにも倒さない)

Lambda:
  コールドスタート時に読み込み
  更新は新しい zip / S3 オブジェクトの差し替えで行う
  (Phase 3 で S3 ETag による更新検知を検討)
```

緊急停止:

```text
policy トップレベルの disabled: true で全発行を停止 (HTTP 503 を返す)
rule 単位では enabled: false で個別に無効化
```

短命 TTL のため、発行を止めれば最大 `max_valid_for_seconds` (デフォルト 15 分) で既存の権限もすべて失効します。README に緊急停止手順として明記します:

```text
1. policy の disabled: true → reload (または Lambda の同時実行数を 0 に)
2. max_valid_for_seconds 経過を待つ (それ以降、有効な証明書は存在しない)
3. CA 鍵漏洩が疑われる場合のみ、サーバ側 TrustedUserCAKeys を差し替える
```

---

## 12. 公開鍵検証と署名処理

### 12.1 公開鍵検証

CA 側では、クライアントから渡された public key を信用しません。検証はすべて `golang.org/x/crypto/ssh` のパーサで行い、外部コマンドを使いません。

検証項目:

```text
空でない
サイズ上限以内
単一行である
ssh.ParseAuthorizedKey でパースできる
key type が allowlist に含まれる
初期版では ssh-ed25519 のみ許可
証明書キー (*-cert-v01@openssh.com) を拒否
```

監査ログには fingerprint (ssh.FingerprintSHA256) を残します。

```json
{
  "public_key_fingerprint": "SHA256:...",
  "key_type": "ssh-ed25519"
}
```

### 12.2 インメモリ署名

署名は `golang.org/x/crypto/ssh` で完結させます。CA 秘密鍵はディスクに書き出しません。

```go
// CA 鍵: mount / Secrets Manager から取得した PEM をメモリ上で parse
signer, err := ssh.ParsePrivateKey(caKeyPEM)

// クライアント公開鍵を parse
pub, _, _, _, err := ssh.ParseAuthorizedKey(reqPublicKey)

// 証明書を構築して署名 (すべてメモリ内)
cert := &ssh.Certificate{
    Key:             pub,
    Serial:          serial,
    CertType:        ssh.UserCert,
    KeyId:           keyID,
    ValidPrincipals: principals,
    ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()),
    ValidBefore:     uint64(now.Add(ttl).Unix()),
    Permissions:     ssh.Permissions{Extensions: extensions},
}
err = cert.SignCert(rand.Reader, signer)

// authorized_keys 形式で返却
out := ssh.MarshalAuthorizedKey(cert)
```

これにより、v2 で必要だった一時ディレクトリ運用 (tmpfs マウント、0700/0600 権限、削除保証、subprocess timeout、引数の扱い) は**仕様ごと不要**になります。

CA 鍵の取り扱いで残る注意は次のみです。

```text
CA 鍵をログ / エラーメッセージに出さない
取得経路 (mount / Secrets Manager / SSM) のアクセス権を最小にする
メモリ上の鍵は起動時に 1 回 parse し、生の PEM bytes は保持しない
```

### 12.3 Signer 抽象化

署名処理は `Signer` インターフェースとして抽象化します。

```text
MVP:    インメモリ署名 (x/crypto/ssh)
将来:   KMS 等の外部署名
        (CA 鍵をプロセスにすら持たない構成。
         crypto.Signer を実装した KMS ラッパを差し込む)
```

`ssh.NewSignerFromSigner` は `crypto.Signer` を受け取れるため、KMS 署名への拡張は自然に実装できます。

### 12.4 CA 鍵の設定

CA 鍵の在処は、フラグまたは環境変数で指定します。URI スキームは使わず、素朴なパス / 値で指定します。

```text
--ca-key-file PATH          フラグでファイルパスを指定
OIDC_SSH_CA_KEY_FILE        環境変数でファイルパスを指定
OIDC_SSH_CA_KEY             環境変数に OpenSSH 形式の秘密鍵を直接入れる
                            (Lambda の環境変数など、ファイルを置けない環境向け)
```

指定の競合は安全側に倒します。

```text
指定がちょうど 1 つ:  起動
指定が 0 個:          起動失敗
複数ソースを同時指定:  起動失敗 (フラグ優先などの暗黙の優先順位を作らない)
```

#### 鍵の生成

```bash
ssh-keygen -t ed25519 -N "" -f ca_key -C "oidc-ssh-ca"
```

```text
ed25519 のみ (MVP)
パスフレーズなしを前提とする
  (サーバ起動時に対話できないため。保護はファイル権限と
   secret store 側で行うことを docs/security.md に明記)
形式は OpenSSH 秘密鍵形式 (ssh.ParsePrivateKey がそのまま読める)
```

#### 起動時の検証 (fail fast)

```text
parse できなければ起動失敗
--ca-key-file / OIDC_SSH_CA_KEY_FILE の場合、ファイル権限が
  0600 より緩ければ (group/other に読み取りがあれば) 起動失敗
起動ログには CA 公開鍵の fingerprint (SHA256:...) のみを出す
  → どの鍵で動いているかを確認でき、秘密情報は出ない
parse 後、生の PEM bytes は保持しない (12.2 の方針どおり)
```

#### デプロイ形態ごとの指定方法

```text
binary + systemd:  LoadCredential + Environment=OIDC_SSH_CA_KEY_FILE=%d/ca_key
                   (6.2 の unit 例参照)
Docker:            secret / volume を mount し OIDC_SSH_CA_KEY_FILE で指定
Lambda (MVP):      OIDC_SSH_CA_KEY に鍵を直接設定
                   (Lambda 環境変数は保存時に暗号化される)
Lambda (Phase 3):  OIDC_SSH_CA_KEY_SECRETSMANAGER_ARN /
                   OIDC_SSH_CA_KEY_SSM_PARAMETER を追加し、
                   起動時に取得する (環境変数の形は同じ流儀で増やす)
```

#### ローテーション

サーバ側の `TrustedUserCAKeys` には複数の CA 公開鍵を並べられるため、ローテーションは無停止で行えます。

```text
1. 新しい CA 鍵を生成
2. 各サーバの TrustedUserCAKeys に新 CA 公開鍵を追記 (新旧併記)
3. oidc-ssh-ca の鍵を新鍵に差し替えて再起動
4. 旧証明書の TTL (max_valid_for_seconds) 経過後、
   TrustedUserCAKeys から旧 CA 公開鍵の行を削除
```

`print-ca-pub` がこの手順の道具になります。MVP では自動化せず、docs/security.md に手順として記載します (key rotation helper は Phase 4)。

---

## 13. JWT 検証仕様

JWT 検証は実績のある Go ライブラリ (`github.com/lestrrat-go/jwx` または `github.com/coreos/go-oidc` を候補) に委ね、自前実装をしません。そのうえで、運用上の仕様を固定します。

### 13.1 検証項目

```text
署名: issuer の JWKS で検証
alg: RS256 のみ許可 (allowlist 方式、none は当然拒否)
iss: policy の issuer と一致
aud: policy の audience と一致
exp / nbf / iat: 検証する
sub / 各 claim: policy の rule と照合
```

### 13.2 JWKS キャッシュ

```text
JWKS はメモリにキャッシュする (TTL: 10 分)
未知の kid が来た場合: 1 回だけ JWKS を再取得し、それでも無ければ deny
JWKS 取得に失敗した場合:
  有効なキャッシュがあればそれを使う
  キャッシュが無ければ deny (発行しない側に倒す)
```

### 13.3 clock skew

```text
exp / nbf / iat の検証に leeway 60 秒を許容する
証明書の valid_after_offset_seconds (デフォルト -30 秒) は
これとは独立に、サーバ側 sshd との時刻ずれ対策として適用する
```

---

## 14. 監査ログ

発行ログは構造化 JSON で出します (標準ライブラリ `log/slog` を使用)。

例:

```json
{
  "event": "certificate_issued",
  "rule": "prod-deploy",
  "principal": "gha-prod-deploy",
  "key_id": "gha:your-org/your-repo:123456789:1",
  "public_key_fingerprint": "SHA256:...",
  "valid_for_seconds": 600,
  "repository": "your-org/your-repo",
  "ref": "refs/heads/main",
  "environment": "production",
  "run_id": "123456789",
  "run_attempt": "1"
}
```

deny 時もイベントとして残します (`certificate_denied`、deny 理由コード付き)。

スタンドアローンでは stdout に出します。Lambda では CloudWatch Logs に出します。

### 14.1 key_id の方針

SSH certificate の `Key ID` は監査で重要です。

GitHub Actions 用:

```text
gha:${repository}:${run_id}:${run_attempt}
```

AWS IAM 経由用:

```text
aws:${aws_role_name}:${aws_session_name}
```

サーバ側ログから GitHub Actions run へ戻れるようにします。展開値は 10.3 のサニタイズ仕様に従います。

---

## 15. sshd 側の設定

対象サーバでは、CA 公開鍵を信頼させます。

```sshconfig
TrustedUserCAKeys /etc/ssh/oidc-ssh-ca.pub

Match User deploy
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

`AuthorizedPrincipalsFile` は、SSH 証明書ログイン時に「この Linux ユーザーへログインしてよい certificate principal は何か」を書くファイルを指定する設定です。

例:

```text
/etc/ssh/auth_principals/deploy
```

```text
gha-prod-deploy
```

この場合、証明書に `gha-prod-deploy` principal が含まれていれば、`deploy` ユーザーへのログインが許可されます。

---

## 16. GitHub Actions example

host key 検証を含めた完全な例です。`known_hosts` はあらかじめ管理者が取得し (`ssh-keyscan` を信頼できる経路で実行)、リポジトリにコミットしておきます。

```yaml
name: Deploy with SSH certificate

on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production

    steps:
      - uses: actions/checkout@v4

      - name: Generate ephemeral SSH key
        run: |
          ssh-keygen -t ed25519 -N "" -f gha_key

      - name: Get GitHub OIDC token
        run: |
          curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=ssh-ca-prod" \
            | jq -r .value > oidc.jwt

      - name: Request SSH certificate
        run: |
          jq -n --arg public_key "$(cat gha_key.pub)" \
            '{ public_key: $public_key }' > request.json

          curl -sS --fail "$OIDC_SSH_CA_URL/sign" \
            -H "Authorization: Bearer $(cat oidc.jwt)" \
            -H "Content-Type: application/json" \
            --data @request.json \
            -o gha_key-cert.pub

      - name: Show certificate
        run: |
          ssh-keygen -L -f gha_key-cert.pub

      - name: Run command
        run: |
          # known_hosts はリポジトリにコミット済みの固定値を使う
          ssh \
            -i gha_key \
            -o CertificateFile=gha_key-cert.pub \
            -o IdentitiesOnly=yes \
            -o UserKnownHostsFile=./.ssh/known_hosts \
            -o StrictHostKeyChecking=yes \
            deploy@example.com \
            'hostname && whoami'
```

リポジトリ側に置くファイル:

```text
.ssh/known_hosts   # 例: example.com ssh-ed25519 AAAA...
```

Phase 4 で host certificate を導入した場合は、known_hosts は次の 1 行に置き換えられます:

```text
@cert-authority *.example.com ssh-ed25519 AAAA... (CA 公開鍵)
```

---

## 17. 簡易運用 workflow example

任意コマンド実行は避け、GitHub Actions の input は choice にします。

```yaml
name: Ops

on:
  workflow_dispatch:
    inputs:
      target:
        required: true
        type: choice
        options:
          - staging
          - production
      command:
        required: true
        type: choice
        options:
          - status
          - restart-app
          - tail-log

permissions:
  id-token: write
  contents: read

jobs:
  run:
    runs-on: ubuntu-latest
    environment: ${{ inputs.target }}

    steps:
      - uses: actions/checkout@v4

      - name: Generate ephemeral SSH key
        run: ssh-keygen -t ed25519 -N "" -f gha_key

      - name: Get GitHub OIDC token
        run: |
          curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=ssh-ca-ops" \
            | jq -r .value > oidc.jwt

      - name: Get SSH certificate
        run: |
          jq -n --arg public_key "$(cat gha_key.pub)" \
            '{ public_key: $public_key }' > request.json

          curl -sS --fail "$OIDC_SSH_CA_URL/sign" \
            -H "Authorization: Bearer $(cat oidc.jwt)" \
            -H "Content-Type: application/json" \
            --data @request.json \
            -o gha_key-cert.pub

      - name: Run ops command
        run: |
          case "${{ inputs.target }}" in
            staging)
              HOST="staging.example.com"
              ;;
            production)
              HOST="prod.example.com"
              ;;
            *)
              echo "invalid target"
              exit 1
              ;;
          esac

          case "${{ inputs.command }}" in
            status)
              REMOTE_CMD='sudo systemctl status myapp --no-pager'
              ;;
            restart-app)
              REMOTE_CMD='sudo systemctl restart myapp && sudo systemctl status myapp --no-pager'
              ;;
            tail-log)
              REMOTE_CMD='sudo journalctl -u myapp -n 100 --no-pager'
              ;;
            *)
              echo "invalid command"
              exit 1
              ;;
          esac

          ssh \
            -i gha_key \
            -o CertificateFile=gha_key-cert.pub \
            -o IdentitiesOnly=yes \
            -o UserKnownHostsFile=./.ssh/known_hosts \
            -o StrictHostKeyChecking=yes \
            deploy@"$HOST" \
            "$REMOTE_CMD"
```

---

## 18. 運用支援機能

コア機能は小さいため、価値は運用支援に出ます。Go の single binary なので、サーバと CLI (check-config / explain など) を 1 つの binary のサブコマンドとして提供できます。

```bash
oidc-ssh-ca serve --config policy.yaml
oidc-ssh-ca check-config policy.yaml
oidc-ssh-ca explain --claims claims.json --policy policy.yaml
oidc-ssh-ca print-ca-pub
oidc-ssh-ca sshd-config-example --user deploy --principal gha-prod-deploy
```

### 18.1 `check-config`

設定ファイルを検証します。

確認内容:

```text
YAML が正しい
rule 名が重複していない
TTL が上限以下
principal が空でない
テンプレート変数が存在する claim を参照している
key_id_template の参照 claim が既知一覧にあるか (警告)
広すぎる match 条件がない
match.aws.session_name の使用はエラー (18.5 参照)
未知 field がない
```

### 18.2 `explain`

claim / caller 情報を与えて、どの rule にマッチするか確認します。

出力例:

```text
matched rule: prod-deploy
principal: gha-prod-deploy
ttl: 600s
key_id: gha:your-org/your-repo:123456789:1
```

claim が JWT に存在しない場合の match 不成立も、このコマンドで原因を特定できるようにします (どの条件で落ちたかを表示)。

### 18.3 `print-ca-pub`

サーバに配置する CA 公開鍵を表示します。

### 18.4 sshd 設定例生成

出力例:

```sshconfig
TrustedUserCAKeys /etc/ssh/oidc-ssh-ca.pub

Match User deploy
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

### 18.5 認可に使ってよい値 / いけない値

利用者の事故を防ぐため、認可 (match) に使える値を仕様として明示します。

```text
認可に使える:
  GitHub OIDC の検証済み claim (repository, ref, environment, ...)
  AWS の account_id / role_name (IAM が保証する値)

認可に使ってはいけない (監査・表示専用):
  aws_session_name
    → caller が role-session-name で自由に指定できる値のため
  JWT の検証されていない自由記述系 claim
```

`match.aws.session_name` はパーサレベルで受け付けず、`check-config` はエラーにします。`key_id_template` への埋め込みは監査用として許可します (サニタイズ対象)。docs にもこの区別を明記します。

---

## 19. 配布

### 19.1 リリース成果物

GoReleaser でマルチプラットフォーム binary をリリースします。

```text
GitHub Releases:
  oidc-ssh-ca_linux_amd64
  oidc-ssh-ca_linux_arm64
  oidc-ssh-ca_darwin_arm64  (check-config / explain をローカルで使う用)
  lambda.zip                (bootstrap binary 入り、provided.al2023 用)
  checksums.txt (+ 署名)

コンテナイメージ (利便提供):
  ghcr.io/<org>/oidc-ssh-ca:latest
```

### 19.2 Dockerfile (multi-stage, 最小イメージ)

ランタイム依存がないため、イメージは scratch / distroless ベースの数 MB になります。

```dockerfile
FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /oidc-ssh-ca ./cmd/oidc-ssh-ca

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /oidc-ssh-ca /oidc-ssh-ca
ENTRYPOINT ["/oidc-ssh-ca", "serve"]
```

イメージに含めないもの:

```text
CA private key
policy.yaml
環境固有の秘密情報
shell / パッケージマネージャ (distroless のため攻撃面が最小)
```

CA 秘密鍵と policy は、外部から mount または secret として渡します。

---

## 20. Ansible role

対象サーバ側の設定用に Ansible role を提供します。

role 名例:

```text
oidc_ssh_ca_trust
```

やること:

```text
CA 公開鍵を配置
/etc/ssh/auth_principals/<user> を作成
sshd_config.d に設定を配置
sshd -t で構文確認
sshd reload
```

利用例:

```yaml
- hosts: app_servers
  become: true
  roles:
    - role: oidc_ssh_ca_trust
      oidc_ssh_ca_public_key: "{{ lookup('file', './oidc-ssh-ca.pub') }}"
      oidc_ssh_ca_users:
        - user: deploy
          principals:
            - gha-prod-deploy
        - user: staging
          principals:
            - gha-staging-deploy
```

生成する設定例:

```sshconfig
TrustedUserCAKeys /etc/ssh/oidc-ssh-ca.pub

Match User deploy
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

---

## 21. AWS 向け発展機能

AWS 専用なら SSM で済む場面も多いため、AWS 機能は中核ではなく発展機能として扱います。

### 21.1 Lambda Function URL (zip デプロイ)

AWS 向けには、`provided.al2023` ランタイム用の zip を提供します。コンテナイメージと ECR は不要です。

```text
GitHub Actions
  ↓ OIDC
AWS STS AssumeRoleWithWebIdentity
  ↓ temporary AWS credentials
Lambda Function URL with AWS_IAM (zip / provided.al2023)
  ↓ SSH certificate
外部サーバ
```

この場合、GitHub OIDC の検証や repo/environment 制御は AWS IAM trust policy に寄せられます。`oidc-ssh-ca` 側は AWS assumed role を見て SSH principal を決定します。

CA 鍵は、MVP 段階では Lambda 環境変数 `OIDC_SSH_CA_KEY` に直接設定し、Phase 3 で Secrets Manager / SSM からの起動時取得 (`OIDC_SSH_CA_KEY_SECRETSMANAGER_ARN` / `OIDC_SSH_CA_KEY_SSM_PARAMETER`) を追加します (12.4 参照)。

AWS IAM 入口版の policy 例:

```yaml
version: 1
disabled: false

defaults:
  valid_after_offset_seconds: -30
  max_valid_for_seconds: 900
  allowed_public_key_types: ["ssh-ed25519"]

rules:
  - name: "aws-iam-prod-deploy"
    enabled: true
    match:
      aws:
        account_id: "123456789012"
        role_name: "github-actions-ssh-ca-prod"
        # session_name は match に使用不可 (18.5 参照)
    certificate:
      principals: ["gha-prod-deploy"]
      valid_for_seconds: 600
      # session_name は監査用として key_id への埋め込みのみ可
      key_id_template: "aws:${aws_role_name}:${aws_session_name}"
```

### 21.2 AWS IAM 入口の利点

```text
GitHub OIDC 検証を AWS IAM に寄せられる
Function URL を AWS_IAM で守れる
CA API を public JWT endpoint にしなくてよい
AWS の CloudTrail / IAM / CloudWatch と相性がよい
```

### 21.3 KMS Signer (発展)

Signer 抽象 (12.3) の KMS 実装を提供し、CA 鍵を Lambda プロセスにすら持たない構成を可能にします。AWS KMS の非対称キー (ECC P-256 等) を `crypto.Signer` としてラップし、`ssh.NewSignerFromSigner` に渡します。

```text
利点: CA 鍵がエクスポート不能になり、漏洩リスクが最小化される
コスト: KMS キー $1/月 + 署名リクエスト課金 (低頻度なら無視できる)
```

### 21.4 Terraform module

AWS デプロイ用 Terraform module を提供します。

作るもの:

```text
Lambda function (zip / provided.al2023)
Lambda Function URL with AWS_IAM
Secrets Manager secret for CA private key (KMS Signer 使用時は不要)
IAM role for Lambda execution
IAM role for GitHub Actions
GitHub OIDC provider
CloudWatch log group
S3 object for policy.yaml
```

利用例:

```hcl
module "oidc_ssh_ca" {
  source = "github.com/your-org/oidc-ssh-ca//terraform/modules/lambda-function-url"

  name        = "oidc-ssh-ca"
  aws_region  = "ap-northeast-1"
  lambda_zip  = "${path.module}/dist/lambda.zip"

  github_repositories = [
    {
      owner       = "your-org"
      repo        = "your-repo"
      environment = "production"
      role_name   = "github-actions-ssh-ca-prod"
    }
  ]

  policy_yaml = file("${path.module}/policy.yaml")
}
```

出力例:

```hcl
output "function_url" {
  value = module.oidc_ssh_ca.function_url
}

output "github_actions_role_arn" {
  value = module.oidc_ssh_ca.github_actions_role_arns["your-org/your-repo:production"]
}

output "ca_public_key" {
  value = module.oidc_ssh_ca.ca_public_key
}
```

### 21.5 AWS 専用でない価値

AWS EC2 だけなら SSM Run Command / Session Manager で十分な場合があります。`oidc-ssh-ca` の価値は、AWS IAM や GitHub OIDC を使いながら、AWS 外の VPS / オンプレ / 他クラウド / bare metal にも SSH 標準機能で接続できる点です。

---

## 22. 既存ツールとの差分

### 22.1 Vault / OpenBao

高機能な secrets / SSH CA 基盤です。ただし個人・小規模には重い場合があります。

`oidc-ssh-ca` はもっと小さく、SSH certificate 発行に特化します。

### 22.2 Teleport

人間ログイン、監査、セッション録画まで含む大きな基盤です。Community Edition には企業規模によるライセンス制限もあります。

`oidc-ssh-ca` は CI / 運用ワークフローからの短命 SSH 権限に集中します。

### 22.3 Certonid / BLESS 系

Lambda SSH CA という発想は近いです。

違いは、`oidc-ssh-ca` は OIDC/JWT claim や GitHub Actions workflow identity を第一級に扱うことです。

### 22.4 opkssh

GitHub Actions OIDC と SSH を結びつける発想は近いです。

`oidc-ssh-ca` は、スタンドアローン CA / Lambda CA として、`policy.yaml` による発行ルール管理を重視します。

なお、この領域は変化が速いため、**公開前に opkssh を含む近隣ツールの最新機能との差分を再確認**し、README の比較表を更新します。

---

## 23. 初期 MVP

最初の MVP は次で十分です。

```text
single static binary (serve + check-config + explain + print-ca-pub)
HTTP /sign endpoint
CA 鍵設定 (--ca-key-file / OIDC_SSH_CA_KEY_FILE / OIDC_SSH_CA_KEY、
  権限チェック、起動時 fingerprint 表示、複数指定はエラー)
GitHub Actions OIDC JWT 検証 (13章の仕様: JWKS キャッシュ / clock skew 含む)
policy.yaml (disabled / enabled フラグ、SIGHUP リロード含む)
key_id_template サニタイズ
ssh-ed25519 public key validation (x/crypto/ssh)
インメモリ証明書署名 (x/crypto/ssh、Signer 抽象化)
structured audit log (log/slog、issued / denied)
GoReleaser によるマルチプラットフォーム binary リリース
systemd unit example
GitHub Actions example (pinned known_hosts 込み)
sshd_config example
緊急停止手順の README 記載
```

MVP で無理に入れないもの:

```text
ブラウザログイン
人間ユーザー向け SSO
DB
複雑な approval
長期セッション管理
独自 SSH server
```

Docker image は MVP に含めてもコストが小さい (multi-stage + distroless で数行) ため、Phase 1 で提供します。

---

## 24. 発展ロードマップ

### Phase 1: スタンドアローン MVP

```text
single binary + systemd unit example
JWT direct mode
policy.yaml (disabled / enabled / SIGHUP reload)
GoReleaser リリース
Docker image (distroless)
GitHub Actions example (pinned known_hosts)
sshd example
```

### Phase 2: 運用支援

```text
check-config 拡充
explain 拡充
structured audit log 改善
Ansible role
```

### Phase 3: AWS / Lambda 対応

```text
Lambda zip (provided.al2023)
Function URL AWS_IAM mode
Secrets Manager / SSM integration (OIDC_SSH_CA_KEY_SECRETSMANAGER_ARN 等)
S3 policy loader (ETag 更新検知)
Terraform module
AWS IAM role matching (session_name は authz 不可)
```

### Phase 4: 拡張

```text
claims_one_of / claims_glob
multiple issuers
Kubernetes ServiceAccount OIDC
GitLab CI OIDC
host certificate 発行 (@cert-authority による known_hosts 簡素化)
KMS Signer (CA 鍵をプロセスに持たない構成)
key rotation helper
emergency disable の拡張 (API 経由の停止など)
```

---

## 25. リポジトリ構成案

```text
oidc-ssh-ca/
  cmd/
    oidc-ssh-ca/
      main.go
  internal/
    policy/        # parse / validate / match
    issuer/        # Signer 抽象 + x/crypto/ssh 実装
    oidc/          # JWT 検証 / JWKS キャッシュ
    server/        # HTTP handler
    audit/         # slog ベースの監査ログ
  Dockerfile
  .goreleaser.yaml
  README.md
  docs/
    design.md
    sshd.md
    policy.md          # claim の存在条件 / authz に使える値の一覧を含む
    security.md        # CA 鍵取り扱い / ローテーション / 緊急停止手順
    aws-lambda.md

  examples/
    github-actions/
      deploy.yml
      ops.yml
      known_hosts.example

    policy/
      github-oidc.yaml
      aws-iam.yaml

    sshd/
      sshd_config.example
      auth_principals.example

    systemd/
      oidc-ssh-ca.service

  terraform/
    modules/
      lambda-function-url/
      github-actions-role/
      ca-secret/
    examples/
      minimal/
      production/

  ansible/
    roles/
      oidc_ssh_ca_trust/
    playbooks/
      install_trust.yml
```

---

## 26. まとめ

`oidc-ssh-ca` は、機能としては小さいツールです。

```text
認証済みの caller を確認する
公開鍵を受け取る
policy にマッチさせる
インメモリで短命 SSH 証明書に署名する
```

しかし、価値は運用支援にあります。

```text
安全なデフォルト
設定が読みやすい
失敗時に危険側へ倒れない
ログで追える
single binary で導入手順が短い
CA 鍵がディスクに触れない
緊急時に確実に止められる
Terraform / Ansible / GitHub Actions example が揃っている
```

これは高機能な認証基盤ではなく、GitHub Actions、OIDC/JWT、OpenSSH certificates、Ansible、shell script を安全につなぐための小さな接着剤です。
