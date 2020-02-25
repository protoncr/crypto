module TGCrypto
  module RSA
    # Represents a RSA private or public key.
    #
    class Key
      # The RSA modulus, a positive integer.
      #
      getter modulus : Int64

      # The RSA public or private exponent, a positive integer.
      #
      getter exponent : Int64

      # Initializes a new key.
      #
      def initialize(modulus : Int, exponent : Int)
        @modulus  = modulus.to_i64
        @exponent = exponent.to_i64
      end

      # Returns `true` if this is a valid RSA key according to `PKCS1`.
      def valid?
        true # TODO
      end

      # Returns a two-element array containing the modulus and exponent.
      #
      def to_a
        [modulus, exponent]
      end
    end
  end
end
