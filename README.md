# Crypto Crystal

Pure Crystal port of [pyrogram/tgcrpto](https://github.com/pyrogram/tgcrpto). Implements various Cryptograpgy algorithms that are especially usefull for Telegram's MTPtoto protocol.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     crypto:
       github: watzon/crypto
   ```

2. Run `shards install`

## API

```crystal
module Crypto
  module AES
    def self.create_encryption_key(key : Bytes) : Slice(UInt32)
    def self.create_decryption_key(key : Bytes) : Slice(UInt32)
    def self.encrypt(data : Bytes, key : Indexable(UInt32)) : Bytes
    def self.decrypt(data : Bytes, key : Indexable(UInt32)) : Bytes
  end

  module CBC
    def self.encrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
    def self.decrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
  end

  module CTR
    def self.xcrypt(data : Bytes, key : Bytes, iv : Bytes, state : Bytes = [0_u8]) : Bytes
  end

  module IGE
    def self.encrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
    def self.decrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
  end

  module Padding
    def self.pkcs7(buffer : Bytes, block_size : Int)
  end
end
```

## Usage

### IGE Mode

**Note:** Data must be padded to match a multiple of the block size `AES::BLOCK_SIZE`.

```crystal
require "crypto"

random = Random.new

# 10 MB of random data + 7 bytes to show padding
data = random.random_bytes(10 * 1024 * 1024 + 7)

key = random.random_bytes(32) # Random key
iv = random.random_bytes(32) # Random iv

# Pad the data using PKCS7
data = Crypto::Padding.pkcs7(data, Crypto::AES::BLOCK_SIZE)

encrypted = Crypto::IGE.encrypt(data, key, iv)
decrypted = Crypto::IGE.decrypt(encrypted, key, iv)

puts data == decrypted
# => true
```

### CTR Mode

```crystal
require "crypto"

random = Random.new

# 10 MB of random data + 7 bytes to show padding
data = random.random_bytes(10 * 1024 * 1024 + 7)

key = random.random_bytes(32) # Random key
iv = random.random_bytes(16) # Random iv

# Pad the data using PKCS7
data = Crypto::Padding.pkcs7(data, Crypto::AES::BLOCK_SIZE)

encrypted = Crypto::CTR.xcrypt(data, key, iv)
decrypted = Crypto::CTR.xcrypt(encrypted, key, iv)

puts data == decrypted
```

### CBC Mode

**Note:** Data must be padded to match a multiple of the block size `AES::BLOCK_SIZE`.

```crystal
require "crypto"

random = Random.new

# 10 MB of random data + 7 bytes to show padding
data = random.random_bytes(10 * 1024 * 1024 + 7)

key = random.random_bytes(32) # Random key
iv = random.random_bytes(16) # Random iv

# Pad the data using PKCS7
data = Crypto::Padding.pkcs7(data, Crypto::AES::BLOCK_SIZE)

encrypted = Crypto::CBC.encrypt(data, key, iv)
decrypted = Crypto::CBC.decrypt(encrypted, key, iv)

puts data == decrypted
```

## Roadmap

- [ ] Cipher Based
  - [ ] AES
    - [ ] 128
    - [ ] 192
    - [x] 256
  - [ ] CBC
    - [ ] 128
    - [ ] 192
    - [x] 256
  - [ ] CTR
    - [ ] 128
    - [ ] 192
    - [x] 256
  - [ ] IGE
    - [ ] 128
    - [ ] 192
    - [x] 256
- [x] Public Key Cryptography
  - [x] RSA
- [ ] Key Derivation Functions
  - [ ] KDF
    - [ ] PBKDF2
- [ ] More?

## Contributing

1. Fork it (<https://github.com/watzon/crypto/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Chris Watson](https://github.com/watzon) - creator and maintainer
