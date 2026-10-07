# frozen_string_literal: true

module RedmineEncryptedCustomFields
  # 鍵の取得元のインターフェース。実装は鍵を DB・プラグイン設定・ログに保存してはならない。
  #
  # 将来の実装（KMS、Vault など）は #key_for で複数の鍵を返せば鍵ローテーションに
  # 対応できる。暗号文には、暗号化に使った鍵の ID が含まれている。
  class KeyProvider
    KEY_BYTES = 32
    KEY_ID_FORMAT = /\A[a-z0-9]{1,16}\z/

    # 新しく暗号化するときに使う鍵の ID。
    def current_key_id
      raise NotImplementedError
    end

    # key_id に対応する 32 バイトの生の鍵。
    def key_for(key_id)
      raise NotImplementedError
    end

    def validate!
      key_for(current_key_id)
      true
    end

    def configured?
      validate!
    rescue Error
      false
    end
  end
end
