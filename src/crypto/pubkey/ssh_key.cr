require "../utils/prime"

module Crypto
  class SSHKey
    SSH_TYPES = {
      "ssh-rsa"             => "rsa",
      "ssh-dss"             => "dsa",
      "ssh-ed25519"         => "ed25519",
      "ecdsa-sha2-nistp256" => "ecdsa",
      "ecdsa-sha2-nistp384" => "ecdsa",
      "ecdsa-sha2-nistp521" => "ecdsa",
    }

    SSHFP_TYPES = {
      "rsa"     => 1,
      "dsa"     => 2,
      "ecdsa"   => 3,
      "ed25519" => 4,
    }

    SSH_CONVERSION   = {"rsa" => ["e", "n"], "dsa" => ["p", "q", "g", "pub_key"]}
    SSH2_LINE_LENGTH = 70 # +1 (for line wrap '/' character) must be <= 72

    # If the key is encrypted, supply the passphrase
    property passphrase : String?

    # Comment to use for the public key
    property comment : String

    # Options prefixed to the public key
    property directives : Array(String)

    def initialize(private_key : PrivateKey,
                   passphrase : String? = nil,
                   comment : String? = nil,
                   directives : Array(String)? = nil)
      @passphrase = passphrase
      @comment = comment || ""
      @directives = directives || [] of String
    end
  end
end
