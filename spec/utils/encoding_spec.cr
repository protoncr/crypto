require "../spec_helper"

alias ASN1 = Crypto::Encoding::ASN1

describe Crypto::Encoding do
  # Test parsing of PEM encoded data
  describe ".parse_pem" do
    it "parses PEM encoded data correctly" do
      pem_data = "-----BEGIN TEST DATA-----\nSGVsbG8gV29ybGQ=\n-----END TEST DATA-----"
      expected_bytes = Bytes[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64]
      parsed_bytes = Crypto::Encoding.parse_pem(pem_data)

      parsed_bytes.should eq expected_bytes
    end
  end

  # Test decoding of DER data
  describe ".decode_der" do
    it "decodes DER data correctly" do
      # Simplified DER data representing two integers
      der_data = Bytes[0x02, 0x01, 0x05, 0x02, 0x01, 0x0A]
      decoded_data = Crypto::Encoding.decode_der(der_data)

      decoded_data.size.should eq 2
      decoded_data[0].should eq BigInt.new(5)
      decoded_data[1].should eq BigInt.new(10)
    end
  end

  describe Crypto::Encoding::ASN1 do
    # Test parsing of simple ASN.1 types with short form length
    it "parses ASN.1 types with short form length correctly" do
      data = Bytes[ASN1::Type::INTEGER.value, 0x03, 0x01, 0x02, 0x03]
      asn1 = ASN1.new(data, 0)

      asn1.type.should eq ASN1::Type::INTEGER
      asn1.size.should eq 3
      asn1.value.should eq Bytes[0x01, 0x02, 0x03]
    end

    # Test handling of long form length encoding
    it "handles long form length encoding correctly" do
      data = Bytes[ASN1::Type::INTEGER.value, 0x81, 0x03, 0x01, 0x02, 0x03]
      asn1 = ASN1.new(data, 0)

      asn1.type.should eq ASN1::Type::INTEGER
      asn1.size.should eq 3
      asn1.value.should eq Bytes[0x01, 0x02, 0x03]
    end

    # Test parsing of multiple ASN.1 elements
    it "parses multiple ASN.1 elements correctly" do
      data = Bytes[ASN1::Type::INTEGER.value, 0x01, 0x05, ASN1::Type::OCTET_STRING.value, 0x01, 0xFF]
      asn1_array = ASN1.decode(data)

      asn1_array.size.should eq 2
      asn1_array[0].type.should eq ASN1::Type::INTEGER
      asn1_array[0].value.should eq Bytes[0x05]
      asn1_array[1].type.should eq ASN1::Type::OCTET_STRING
      asn1_array[1].value.should eq Bytes[0xFF]
    end

    # Test conversion of ASN.1 value to BigInt
    it "converts ASN.1 value to BigInt correctly" do
      data = Bytes[ASN1::Type::INTEGER.value, 0x02, 0x01, 0xFF]
      asn1 = ASN1.new(data, 0)
      bigint = asn1.to_big_i

      bigint.should eq BigInt.new("1FF", 16)
    end
  end
end
