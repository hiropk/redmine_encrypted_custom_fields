# LT デモ手順メモ（2026-10-08）

デモの持ち時間は **1 分半くらい**。スライド 9 枚目「DEMO」でブラウザに切り替える。

- チケット: **#3786**「RedmineにOAuth用アプリケーションを登録する」（プロジェクト `testproject_enc_cf`）
- 暗号化フィールド: **「シークレットキー」（ID 30）**
- ログインユーザー: **lychee-a**（管理者。閲覧・復号・編集の権限あり）
- 入力する値: `demo-oauth-secret-1008`

コマンドはすべて **Mac のターミナル**で、`~/Agileware/hiropk_claude_dev/src/redmine` から実行する。

---

## 0. 直前チェック（発表の 10 分前）

```bash
cd ~/Agileware/hiropk_claude_dev/src/redmine

# Redmine が動いているか（200 が出れば OK）
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000/login

# 暗号鍵がコンテナに渡っているか（45 が出れば OK。0 や 1 なら鍵がない）
docker exec hiropk_claude_dev_devcontainer-redmine-1 printenv REDMINE_ENCRYPTED_FIELDS_KEY | wc -c
```

200 が出ないときは、Redmine を再起動する。

```bash
docker restart hiropk_claude_dev_devcontainer-redmine-1
```

再起動後、`curl` が 200 を返すまで 30 秒ほど待つ。

### ブラウザのタブを 3 つ開いておく（この順番で）

1. スライド: `lt/index.html`（F キーで全画面）
2. チケット: http://localhost:3000/issues/3786 （lychee-a でログインしておく）
3. 監査ログ: http://localhost:3000/admin/encrypted_custom_field_audit_logs

- ブラウザは **Cmd + `+`** で 150% くらいに拡大しておく（後ろの席から読めるように）
- ターミナルも **Cmd + `+`** で文字を大きくしておく
- 念のため、各画面のスクリーンショットを撮っておく（デモが動かなかったときの保険）

---

## 1. 値を入れて保存する（タブ 2）

> 「OAuth のシークレットを、チケットのカスタムフィールドに保存してみます」

1. チケット #3786 で **「編集」** を押す
2. 「シークレットキー」の **「置き換える」** を選ぶ（入力し始めると自動で選ばれる）
3. `demo-oauth-secret-1008` を入力する
4. **「送信」** を押す

**期待する結果**: 詳細画面の「シークレットキー」が `••••••••` になり、横に **「表示」** ボタンが出る。

> 「画面では、いつもマスクされています」

---

## 2. DB をのぞく（ターミナル）

> 「では DB には何が入っているか、直接見てみます」

```bash
docker exec hiropk_claude_dev_devcontainer-redmine-db-1 psql -U postgres -d redmine_6_1_stable_development \
  -c "select customized_id as issue, left(value, 60) as value from custom_values where custom_field_id = 30;"
```

**期待する結果**: `ecf:v1:k1:...` という読めない文字列だけが入っている。

> 「DB には暗号文しか入っていません」

余裕があれば、平文がどこにもないことも見せる（`0` が出れば OK）。

```bash
docker exec hiropk_claude_dev_devcontainer-redmine-db-1 psql -U postgres -d redmine_6_1_stable_development \
  -c "select count(*) from custom_values where value like '%demo-oauth-secret%';"
```

---

## 3. 「表示」で見る（タブ 2）

> 「権限のある人だけ、表示ボタンで中身を見られます」

1. **「表示」** を押す → `demo-oauth-secret-1008` が出る
2. 「隠す」を押すか、**30 秒待つ** とマスクに戻る

> 「出しっぱなしにはならず、30 秒で自動的に隠れます」

---

## 4. 監査ログを見る（タブ 3）

> 「そして、誰がいつ見たかは全部記録されています」

監査ログのタブを **再読み込み（Cmd + R）** する。

**期待する結果**: 一番上に「lychee-a / #3786 / シークレットキー / 復号表示 / IP アドレス」の行が増えている。

ブラウザで開けないときは、コマンドで確認する。

```bash
docker exec hiropk_claude_dev_devcontainer-redmine-db-1 psql -U postgres -d redmine_6_1_stable_development \
  -c "select created_on, action, user_id, issue_id, ip_address from encrypted_custom_field_audit_logs order by id desc limit 3;"
```

> 「というわけで、しまう・見せない・見る・残す、ができました」→ スライドに戻って最後の 1 枚へ

---

## おまけ（時間が余ったら）: ログにも出ていない

手順 1 で保存したときのリクエストログで、値が `[FILTERED]` になっていることを見せる。

```bash
grep -o '"encrypted_value"=>"[^"]*"' log/development.log | tail -1
```

**期待する結果**: `"encrypted_value"=>"[FILTERED]"`

---

## 困ったとき

| 症状 | 原因と対処 |
|---|---|
| 「表示」ボタンが出ない | lychee-a でログインしているか確認する。ログアウトしていたらログインし直す |
| 「表示」を押すとエラーが出る | 鍵が渡っていない可能性がある。手順 0 の `printenv` を確認し、45 でなければ Redmine を再起動する |
| 保存すると「暗号鍵が未設定または不正です」と出る | 同上 |
| ボタンを押しても何も起きない | JS が古い可能性がある。**Cmd + Shift + R** で強制再読み込みする |
| ページが開かない | Redmine を再起動する（`docker restart hiropk_claude_dev_devcontainer-redmine-1`） |
| どうしても動かない | 撮っておいたスクリーンショットで説明する。「本番あるある」で笑いに変える |

---

## 話す順番だけ（これだけ見ればいい版）

1. 編集 → 置き換える → `demo-oauth-secret-1008` → 送信 → **マスクされた**
2. ターミナルで DB → **`ecf:v1:...` だけ**
3. 「表示」→ **見えた** → 30 秒で消える
4. 監査ログを再読み込み → **記録が増えた**
