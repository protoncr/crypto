require "./key"
require "./pkcs1"

module TGCrypto
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

      def self.generate(bits, exponent = 65537)
        unless Prime.prime?(bits) && Prime.prime?(exponent)
          raise ArgumentError.new("both numbers must be prime.")
        end

        if bits == exponent
          raise ArgumentError.new("p and q cannot be equal")
        end

        bits = bits.to_i64
        exponent = exponent.to_i64

        # n = pq
        n = bits * exponent

        # Phi is the totient of n
        phi = (bits - 1) * (exponent - 1)

        # Choose an integer e such that e and phi(n) are coprime
        e = rand(1_i64..phi)

        # Use Euclid's Algorithm to verify that e and phi(n) are comprime
        g = e.gcd(phi)
        while g != 1
          e = rand(1_i64..phi)
          g = e.gcd(phi)
        end

        # Use Extended Euclid's Algorithm to generate the private key
        d = Math.mod_inverse(e, phi)

        # Return the new keypair
        new(Key.new(e, n), Key.new(d, n))
      end

      # Returns `true` if this is a valid RSA key pair according to
      # `PKCS1`.
      #
      def valid?
        private_key.valid? && public_key.valid?
      end

      # Returns the byte size of this key pair.
      #
      def bytesize
        Math.log256(modulus).ceil
      end

      # Returns the bit size of this key pair.
      #
      def bitsize
        Math.log2(modulus).ceil
      end

      # ditto
      def size
        bitsize
      end

      # Returns the RSA modulus for this key pair.
      #
      def modulus
        private_key ? private_key.modulus : public_key.modulus
      end

      # Encrypts the given `plaintext` using the public key from this key
      # pair.
      #
      # For `options` see `#encrypt_integer`.
      #
      def encrypt(plaintext : Int32 | Int64 | String | IO)
        case plaintext
        when Int    then encrypt_integer(plaintext)
        when String then PKCS1.i2osp(encrypt_integer(PKCS1.os2ip(plaintext)))
        when IO     then PKCS1.i2osp(encrypt_integer(PKCS1.os2ip(plaintext.gets_to_end)))
        end
      end

      # Decrypts the given `plaintext` using the private key from this key
      # pair.
      #
      def decrypt(plaintext : Int32 | Int64 | String | IO)
        case plaintext
        when Int    then decrypt_integer(plaintext)
        when String then PKCS1.i2osp(decrypt_integer(PKCS1.os2ip(plaintext)))
        when IO     then PKCS1.i2osp(decrypt_integer(PKCS1.os2ip(plaintext.gets_to_end)))
        end
      end

      # Signs the given `plaintext` using the private key from this key
      # pair.
      #
      def sign(plaintext : Int32 | Int64 | String | IO)
        case plaintext
        when Int    then sign_integer(plaintext)
        when String then PKCS1.i2osp(sign_integer(PKCS1.os2ip(plaintext)))
        when IO     then PKCS1.i2osp(sign_integer(PKCS1.os2ip(plaintext.gets_to_end)))
        end
      end

      # Verifies the signature using the private key from this key pair.
      #
      def verify(signature : Int32 | Int64 | String,
               plaintext : Int32 | Int64 | String | IO,
               padding = nil)
        signature = case signature
          when Int    then signature
          when String then PKCS1.os2ip(signature)
          when IO     then PKCS1.os2ip(signature.gets_to_end)
          end
        plaintext = case plaintext
          when Int    then plaintext
          when String then PKCS1.os2ip(plaintext)
          when IO     then PKCS1.os2ip(plaintext.gets_to_end)
          end
        verify_integer(signature, plaintext)
      end


      protected def encrypt_integer(plaintext)
        PKCS1.rsaep(public_key, plaintext)
      end


      protected def decrypt_integer(ciphertext)
        PKCS1.rsadp(private_key, ciphertext)
      end


      protected def sign_integer(plaintext)
        PKCS1.rsasp1(private_key, plaintext)
      end


      protected def verify_integer(signature, plaintext)
        PKCS1.rsavp1(public_key, signature).eql?(plaintext)
      end
    end
  end
end
