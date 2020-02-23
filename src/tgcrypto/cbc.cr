require "./aes"

module TGCrypto
  module CBC
    # Takes a 16 bit input and a 60 bit key and encrypt the input
    # using CBC256.
    def self.encrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8))
      self.xcrypt(data, key, iv, true)
    end

    # Takes a 16 bit input and a 60 bit key and decrypt the input
    # using CBC256.
    def self.decrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8))
      self.xcrypt(data, key, iv, false)
    end

    private def self.xcrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8), encrypt : Bool)
      unless data.size > 0
        raise "data byte size must not be zero"
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

      output = data.dup.as(Array(UInt8))

      if encrypt
        enc_key = AES.create_encryption_key(key)

        (0...data.size).step(AES::BLOCK_SIZE).each do |i|
          (0...AES::BLOCK_SIZE).each do |j|
            output[i + j] ^= iv[j]
          end
          encrypted = AES.encrypt(output[i, AES::BLOCK_SIZE], enc_key)
          output[i, AES::BLOCK_SIZE] = encrypted
          iv = encrypted
        end
      else
        puts iv
        next_iv = Array(UInt8).new(AES::BLOCK_SIZE)
        dec_key = AES.create_decryption_key(key)

        (0...data.size).step(AES::BLOCK_SIZE).each do |i|
          next_iv = output[i, AES::BLOCK_SIZE]
          output[i, AES::BLOCK_SIZE] = AES.decrypt(output[i, AES::BLOCK_SIZE], dec_key)
          (0...AES::BLOCK_SIZE).each do |j|
            output[i + j] ^= iv[j]
          end
          iv = next_iv
        end
      end

      output
    end
  end
end
