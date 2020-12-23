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
      def valid?
        true # TODO
      end

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
    end

    class PrivateKey < Key
      getter n : BigInt
      getter e : BigInt
      getter d : BigInt
      getter p : BigInt
      getter q : BigInt

      getter exp1 : BigInt
      getter exp2 : BigInt
      getter coef : BigInt

      def initialize(n, e, d, p, q)
        @n = n.to_big_i
        @e = e.to_big_i
        @d = d.to_big_i
        @p = p.to_big_i
        @q = q.to_big_i

        @exp1 = @d % (@p - 1)
        @exp2 = @d % (@q - 1)
        @coef = Math.modinv(@q, @p)
      end
    end
  end
end
