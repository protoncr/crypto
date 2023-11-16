require "big"

module Crypto
  module RSA
    # Represents a RSA private or public key.
    #
    abstract class Key
      # The RSA modulus, a positive integer.
      #
      abstract def n : BigInt

      # The RSA public or private exponent, a positive integer.
      #
      abstract def e : BigInt

      # Returns `true` if this is a valid RSA key according to `PKCS1`.
      abstract def valid? : Bool

      # Returns a two-element array containing the modulus and exponent.
      #
      def to_a
        [n, e]
      end
    end

    class PublicKey < Key
      getter n : BigInt
      getter e : BigInt

      def initialize(n, e)
        @n = n.to_big_i
        @e = e.to_big_i
      end

      def self.load_pkcs1(key : String | Bytes, format : Crypto::Encoding::CertEncoding = :pem)
        key = key.to_slice
        key = Crypto::Encoding.parse_pem(key) if format.pem?
        vals = Crypto::Encoding.decode_der(key)
        n, e = vals
        new(n, e)
      end

      def valid? : Bool
        n > 0 && e > 0 && e.odd?
      end
    end

    class PrivateKey < PublicKey
      getter d : BigInt
      getter p : BigInt
      getter q : BigInt

      getter exp1 : BigInt
      getter exp2 : BigInt
      getter coef : BigInt

      def initialize(n, e, d, p, q)
        super(n, e)
        @d = d.to_big_i
        @p = p.to_big_i
        @q = q.to_big_i

        @exp1 = @d % (@p - 1)
        @exp2 = @d % (@q - 1)
        @coef = Math.modinv(@q, @p)
      end

      def valid? : Bool
        return false unless super && d > 0 && p > 0 && q > 0
        return false unless n == p * q

        phi_n = (p - 1) * (q - 1)
        e < phi_n
      end
    end
  end
end
