require "./aes"

module TGCrypto
  module CTR
    # Uses CTR two way encryption to encrypt and decrypt data.
    # Takes an optional one byte array as a `state` parameter,
    # used to keep track of the position in a stream.
    def self.xcrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8), state : Indexable(UInt8) = [0_u8])
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
        "state value must be in range 0..15"
      end

      output = data.dup.as(Array(UInt8))
      enc_key = AES.create_encryption_key(key)
      chunk = AES.encrypt(iv, enc_key)

      (0...data.size).step(AES::BLOCK_SIZE).each do |i|
        (0...Math.min(data.size - 1, AES::BLOCK_SIZE)).each do |j|
          output[i + j] ^= chunk[state[0]]
          state.to_unsafe[0] += 1

          if state[0] >= AES::BLOCK_SIZE
            state[0] = 0_u8
          end

          if state[0] == 0
            k = AES::BLOCK_SIZE - 1
            (0..(AES::BLOCK_SIZE - 1)).reverse_each do |k|
              unless (iv[k] += 1).zero?
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
