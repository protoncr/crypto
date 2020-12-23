require "big"

module Crypto
  module RSA
    # Represents a RSA private or public key.
    #
    class Key
      # The RSA modulus, a positive integer.
      #
      getter modulus : BigInt

      # The RSA public or private exponent, a positive integer.
      #
      getter exponent : BigInt

      # Initializes a new key.
      #
      def initialize(modulus, exponent)
        @modulus  = modulus.to_big_i
        @exponent = exponent.to_big_i
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
