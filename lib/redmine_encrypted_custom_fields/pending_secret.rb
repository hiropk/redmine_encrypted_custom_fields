# frozen_string_literal: true

module RedmineEncryptedCustomFields
  # フォームや API から受け付けた、まだ保存していない新しい平文。
  # メモリ上の CustomFieldValue#value にだけ存在する。
  #
  # Redmine の汎用コード（履歴、ビュー、メーラー、他プラグイン）がカスタムフィールドの値に
  # #to_s や #inspect を呼ぶことがあるため、どちらもマスクを返す。
  # 平文には #plaintext からしかアクセスできない。
  #
  # ユーザー入力は常に String か Hash であり、このクラスのインスタンスにはならない。
  # そのため、入力の接頭辞を信用しなくても「新しい平文」と「保存済みの暗号文」を区別できる。
  class PendingSecret
    def initialize(plaintext)
      @plaintext = plaintext.to_s.dup.freeze
      @sealed = {}
    end

    attr_reader :plaintext

    def blank?
      @plaintext.blank?
    end

    def present?
      !blank?
    end

    # 所有オブジェクトとフィールドの組ごとに 1 回だけ暗号化し、
    # 同じリクエスト内で同じオブジェクトを何度保存しても再暗号化しない。
    def seal(aad)
      @sealed[aad] ||= Cipher.encrypt(@plaintext, aad: aad)
    end

    def to_s
      MASK_TEXT
    end

    def as_json(*)
      MASK_TEXT
    end

    def inspect
      "#<#{self.class.name} [FILTERED]>"
    end
  end
end
