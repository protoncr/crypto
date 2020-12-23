require "../spec_helper"

describe Crypto::CBC do
  describe ".encrypt" do
    it "should encrypt a buffer" do
      key = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      603DEB10 15CA71BE 2B73AEF0 857D7781
      1F352C07 3B6108D7 2D9810A3 0914DFF4
      TEXT

      iv = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      00010203 04050607 08090A0B 0C0D0E0F
      TEXT

      plaintext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      6BC1BEE2 2E409F96 E93D7E11 7393172A
      AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
      30C81C46 A35CE411 E5FBC119 1A0A52EF
      F69F2445 DF4F9B17 AD2B417B E66C3710
      TEXT

      ciphertext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6
      9CFC4E96 7EDB808D 679F777B C6702C7D
      39F23369 A9D9BACF A530E263 04231461
      B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B
      TEXT

      encrypted = Crypto::CBC.encrypt(plaintext, key, iv)
      encrypted.should eq(ciphertext)
    end
  end

  describe ".decrypt" do
    it "should decrypt an encrypted buffer" do
      key = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      603DEB10 15CA71BE 2B73AEF0 857D7781
      1F352C07 3B6108D7 2D9810A3 0914DFF4
      TEXT

      iv = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      00010203 04050607 08090A0B 0C0D0E0F
      TEXT

      ciphertext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6
      9CFC4E96 7EDB808D 679F777B C6702C7D
      39F23369 A9D9BACF A530E263 04231461
      B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B
      TEXT

      plaintext = <<-TEXT.gsub(" ", "").gsub("\n", "").hexbytes
      6BC1BEE2 2E409F96 E93D7E11 7393172A
      AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
      30C81C46 A35CE411 E5FBC119 1A0A52EF
      F69F2445 DF4F9B17 AD2B417B E66C3710
      TEXT

      decrypted = Crypto::CBC.decrypt(ciphertext, key, iv)
      decrypted.should eq(plaintext)
    end

    describe "exceptions" do
      it "should raise if the data is empty" do
        expect_raises(Exception, "data must not be empty") do
          Crypto::CBC.encrypt(Bytes.new(0), RANDOM.random_bytes(32), RANDOM.random_bytes(16))
        end
      end

      it "should raise if the key size is not 32 bytes" do
        expect_raises(Exception, "key byte size must be 32 bytes exactly") do
          Crypto::CBC.encrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(31), RANDOM.random_bytes(16))
        end
      end

      it "should raise if the iv size is not 16 bytes" do
        expect_raises(Exception, "iv byte size must be 16 bytes exactly") do
          Crypto::CBC.encrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(32), RANDOM.random_bytes(15))
        end
      end
    end
  end
end
