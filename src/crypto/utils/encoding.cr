require "big"

module Crypto
  module Encoding
    enum CertEncoding
      PEM
      DER
    end

    def self.parse_pem(pem_data : String | Bytes) : Bytes
      # Strip PEM headers and decode base64
      pem_data = pem_data.is_a?(String) ? pem_data : String.new(pem_data)
      pem_body = pem_data.lines[1..-2].join
      Base64.decode(pem_body)
    end

    def self.decode_der(der_data : String | Bytes) : Array(BigInt)
      # Decode DER data to extract `n`, `e`, and other fields
      der_data = der_data.is_a?(String) ? der_data.to_slice : der_data
      asn1_data = ASN1.decode(der_data)
      asn1_data.map { |asn1| asn1.to_big_i }
    end

    class ASN1
      enum Type
        INTEGER = 0x02
        BIT_STRING = 0x03
        OCTET_STRING = 0x04
        NULL = 0x05
        OBJECT_IDENTIFIER = 0x06
        SET = 0x11
        PRINTABLE_STRING = 0x13
        IA5_STRING = 0x16
        UTC_TIME = 0x17
        GENERALIZED_TIME = 0x18
        SEQUENCE = 0x30
        BMP_STRING = 0x1e
      end

      getter type : Type
      getter size : Int32
      getter value : Bytes

      def initialize(data : Bytes, offset : Int32)
        @type = Type.new(data[offset])

        length_byte = data[offset + 1]

        if length_byte < 128
          # Short form length
          @size = length_byte.to_i32
          value_start = offset + 2
        else
          # Long form length
          num_length_bytes = length_byte.to_i32 & 0x7F
          @size = 0
          value_start = offset + 2 + num_length_bytes

          num_length_bytes.times do |i|
            @size = (@size << 8) | data[offset + 2 + i].to_i32
          end
        end

        @value = data[value_start, @size]
      end

      def self.decode(data : Bytes) : Array(ASN1)
        asn1 = [] of ASN1
        offset = 0
        while offset < data.size
          asn1_element = new(data, offset)
          case asn1_element.type
          when Type::SEQUENCE
            asn1.concat(decode(asn1_element.value))
          else
            asn1 << asn1_element
          end
          offset += 2 + asn1_element.size + (asn1_element.size >= 128 ? (data[offset + 1].to_i32 & 0x7F) : 0)
        end
        asn1
      end

      # Converts the value to a BigInt
      def to_big_i : BigInt
        case @type
        when Type::INTEGER
          BigInt.new(@value.hexstring, 16)
        when Type::BMP_STRING
          BigInt.new(String.new(@value), 16)
        else
          raise "Invalid ASN1 type for conversion to BigInt: #{@type}"
        end
      end
    end
  end
end
