require "./aes"

module TGCrypto
  module CTR
    # Encrypt/decrypt a buffer using CTR256.
    #
    # `data` must be a non-empty buffer who's length is a multiple
    # of 16 bytes. `key` must be a 32 byte encryption key and `iv` must
    # be 16 bytes.
    def self.xcrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8), state : Indexable(UInt8) = [0_u8]) : Array(UInt8)
      unless data.size > 0
        raise "data must not be empty"
      end

      unless data.size % 16 == 0
        raise "data byte size must be a multiple of 16"
      end

      unless key.size == 32
        raise "key byte size must be 32 bytes exactly"
      end

      unless iv.size == 16
        raise "iv byte size must be 16 bytes exactly"
      end

      unless state.size == 1
        raise "state must be exactly one byte"
      end

      unless state[0].in?(0..15)
        raise "state value must be in range 0..15"
      end

      output = data.to_a.dup
      iv = iv.to_a.dup
      key = key.to_a.dup

      enc_key = AES.create_encryption_key(key)
      chunk = AES.encrypt(iv, enc_key)

      (0...data.size).step(AES::BLOCK_SIZE).each do |i|
        (0...Math.min(data.size - 1, AES::BLOCK_SIZE)).each do |j|
          output[i + j] ^= chunk[state[0]]
          state[0] += 1

          if state[0] >= AES::BLOCK_SIZE
            state[0] = 0_u8

            (0...AES::BLOCK_SIZE).reverse_each do |k|
              unless (iv[k] &+= 1).zero?
                break
              end
            end

            chunk = AES.encrypt(iv, enc_key)
          end
        end
      end

      output
    end
  end
end
