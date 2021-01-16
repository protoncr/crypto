require "./key"
require "./pkcs1"

module Crypto
  module RSA
    class KeyPair
      getter private_key : Key?

      getter public_key : Key?

      # Initializes a new key pair.
      #
      def initialize(@private_key = nil, @public_key = nil)
        unless @private_key || @public_key
          raise "At least one private key or public key is required"
        end
      end

      def self.generate(bits, exponent = 65537, accurate = true)
        if bits < 16
          raise "Key too small"
        end

        p, q, e, d = {0, 0, 0, 0}

        loop do
          # Regenerate p and q values, until calculate_keys doesn't raise
          p, q = self.find_pq(bits // 2, accurate)
          begin
            e, d = self.calculate_keys_custom_exponent(p, q, exponent: exponent)
            break
          rescue ex
          end
        end

        # Create the key objects
        n = p * q

        # Return the new keypair
        new(PrivateKey.new(n, e, d, p, q), PublicKey.new(n, e))
      end

      # Returns `true` if this is a valid RSA key pair according to
      # `PKCS1`.
      #
      def valid?
        private_key.try &.valid? && public_key.try &.valid?
      end

      # Returns the byte size of this key pair.
      #
      def bytesize
        Math.log256(modulus).ceil.to_i32
      end

      # Returns the bit size of this key pair.
      #
      def bitsize
        Math.log2(modulus).ceil.to_i32
      end

      # ditto
      def size
        bitsize
      end

      # Returns the RSA modulus for this key pair.
      #
      def modulus
        private_key ? private_key.not_nil!.n : public_key.not_nil!.n
      end

      # Encrypts the given `plaintext` using the public key from this key
      # pair.
      def encrypt(plaintext)
        case plaintext
        when Int           then encrypt_integer(plaintext)
        when String, Bytes then PKCS1.i2osp(encrypt_integer(PKCS1.os2ip(plaintext)))
        when IO            then PKCS1.i2osp(encrypt_integer(PKCS1.os2ip(plaintext.read)))
        else
          raise ArgumentError.new(plaintext.inspect) # FIXME
        end
      end

      # Decrypts the given `ciphertext` using the private key from this key
      # pair.
      def decrypt(ciphertext)
        case ciphertext
        when Int           then decrypt_integer(ciphertext)
        when String, Bytes then PKCS1.i2osp(decrypt_integer(PKCS1.os2ip(ciphertext)))
        when IO            then PKCS1.i2osp(decrypt_integer(PKCS1.os2ip(ciphertext.gets_to_end)))
        else
          raise ArgumentError.new(ciphertext.inspect) # FIXME
        end
      end

      # Signs the given `plaintext` using the private key from this key pair.
      def sign(plaintext)
        case plaintext
        when Int           then sign_integer(plaintext)
        when String, Bytes then PKCS1.i2osp(sign_integer(PKCS1.os2ip(plaintext)))
        when IO            then PKCS1.i2osp(sign_integer(PKCS1.os2ip(plaintext.gets_to_end)))
        else
          raise ArgumentError.new(plaintext.inspect) # FIXME
        end
      end

      # Verifies the given `signature` using the public key from this key
      # pair.
      def verify(signature, plaintext)
        signature = case signature
                    when Int           then signature
                    when String, Bytes then PKCS1.os2ip(signature)
                    when IO            then PKCS1.os2ip(signature.gets_to_end)
                    else
                      raise ArgumentError.new(signature.inspect) # FIXME
                    end
        plaintext = case plaintext
                    when Int           then plaintext
                    when String, Bytes then PKCS1.os2ip(plaintext)
                    when IO            then PKCS1.os2ip(plaintext.gets_to_end)
                    else
                      raise ArgumentError.new(plaintext.inspect) # FIXME
                    end
        verify_integer(signature, plaintext)
      end

      protected def encrypt_integer(plaintext)
        PKCS1.rsaep(public_key.not_nil!, plaintext)
      end

      protected def decrypt_integer(ciphertext)
        PKCS1.rsadp(private_key.not_nil!, ciphertext)
      end

      protected def sign_integer(plaintext)
        PKCS1.rsasp1(private_key.not_nil!, plaintext)
      end

      protected def verify_integer(signature, plaintext)
        PKCS1.rsavp1(public_key.not_nil!, signature) == plaintext
      end

      private def self.find_pq(nbits, accurate = true)
        total_bits = nbits * 2

        shift = nbits // 16
        pbits = nbits + shift
        qbits = nbits - shift

        p = Crypto::Prime.random(pbits).to_big_i
        q = Crypto::Prime.random(qbits).to_big_i

        is_acceptable = ->(p : BigInt, q : BigInt) {
          if p == q
            false
          elsif !accurate
            true
          else
            found_size = (p * q).bit_length
            total_bits == found_size
          end
        }

        change_p = false
        while !is_acceptable.call(p, q)
          puts "foo"
          # Change p on one iteration and q on the other
          if change_p
            p = Crypto::Prime.random(pbits).to_big_i
          else
            q = Crypto::Prime.random(qbits).to_big_i
          end
          change_p = !change_p
        end

        {Math.max(p, q), Math.min(p, q)}
      end

      private def self.calculate_keys_custom_exponent(p, q, exponent)
        p = p.to_big_i
        q = q.to_big_i
        exponent = exponent.to_big_i

        phi_n = (p - 1) * (q - 1)

        d = Math.modinv(exponent, phi_n)
        if (exponent * d) % phi_n != 1
          raise "e #{exponent} and d #{d} are not multi. inv. modulo phi_n #{phi_n}"
        end

        {exponent, d}
      end
    end
  end
end
