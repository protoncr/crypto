require "../../spec_helper"

describe Crypto::CTR do
  describe ".xcrypt" do
    it "should encrypt a buffer" do
      key = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      603DEB10 15CA71BE 2B73AEF0 857D7781
      1F352C07 3B6108D7 2D9810A3 0914DFF4
      TEXT

      iv = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF
      TEXT

      plaintext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      6BC1BEE2 2E409F96 E93D7E11 7393172A
      AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
      30C81C46 A35CE411 E5FBC119 1A0A52EF
      F69F2445 DF4F9B17 AD2B417B E66C3710
      TEXT

      ciphertext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      601EC313 775789A5 B7A7F504 BBF3D228
      F443E3CA 4D62B59A CA84E990 CACAF5C5
      2B0930DA A23DE94C E87017BA 2D84988D
      DFC9C58D B67AADA6 13C2DD08 457941A6
      TEXT

      encrypted = Crypto::CTR.xcrypt(plaintext, key, iv)
      encrypted.should eq(ciphertext)
    end

    it "should decrypt an encrypted buffer" do
      key = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      603DEB10 15CA71BE 2B73AEF0 857D7781
      1F352C07 3B6108D7 2D9810A3 0914DFF4
      TEXT

      iv = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF
      TEXT

      ciphertext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      601EC313 775789A5 B7A7F504 BBF3D228
      F443E3CA 4D62B59A CA84E990 CACAF5C5
      2B0930DA A23DE94C E87017BA 2D84988D
      DFC9C58D B67AADA6 13C2DD08 457941A6
      TEXT

      plaintext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      6BC1BEE2 2E409F96 E93D7E11 7393172A
      AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
      30C81C46 A35CE411 E5FBC119 1A0A52EF
      F69F2445 DF4F9B17 AD2B417B E66C3710
      TEXT

      decrypted = Crypto::CTR.xcrypt(ciphertext, key, iv)
      decrypted.should eq(plaintext)
    end

    describe "exceptions" do
      it "should raise if the data is empty" do
        expect_raises(Exception, "data must not be empty") do
          Crypto::CTR.xcrypt(Bytes.new(0), RANDOM.random_bytes(32), RANDOM.random_bytes(16))
        end
      end

      it "should raise if the data size is not a multiple of 16" do
        expect_raises(Exception, "data byte size must be a multiple of 16") do
          Crypto::CTR.xcrypt(RANDOM.random_bytes(12), RANDOM.random_bytes(32), RANDOM.random_bytes(16))
        end
      end

      it "should raise if the key size is not 32 bytes" do
        expect_raises(Exception, "key byte size must be 32 bytes exactly") do
          Crypto::CTR.xcrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(31), RANDOM.random_bytes(16))
        end
      end

      it "should raise if the iv size is not 16 bytes" do
        expect_raises(Exception, "iv byte size must be 16 bytes exactly") do
          Crypto::CTR.xcrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(32), RANDOM.random_bytes(15))
        end
      end

      it "should raise if the state is not one byte" do
        expect_raises(Exception, "state must be exactly one byte") do
          Crypto::CTR.xcrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(32), RANDOM.random_bytes(16), Bytes[0_u8, 1_u8])
        end
      end

      it "should raise if the state's byte is not in the range 0..15'" do
        expect_raises(Exception, "state value must be in range 0..15") do
          Crypto::CTR.xcrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(32), RANDOM.random_bytes(16), Bytes[16_u8])
        end
      end
    end
  end
end
