# TGCrypto Crystal

Pure Crystal port of [pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto). Implements various Cryptograpgy algorithms that are especially usefull for Telegram's MTPtoto protocol.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     tgcrypto:
       github: watzon/tgcrypto
   ```

2. Run `shards install`

## API

```crystal
module TGCrypto
  module AES
    def self.create_encryption_key(key : Indexable(UInt8)) : Array(UInt32)
    def self.create_decryption_key(key : Indexable(UInt8)) : Array(UInt32)
    def self.encrypt(data : Indexable(UInt8), key : Indexable(UInt32)) : Array(UInt8)
    def self.decrypt(data : Indexable(UInt8), key : Indexable(UInt32)) : Array(UInt8)
  end

  module CBC
    def self.encrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8)) : Array(UInt8)
    def self.decrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8)) : Array(UInt8)
  end

  module CTR
    def self.xcrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8), state : Indexable(UInt8) = [0_u8]) : Array(UInt8)
  end

  module IGE
    def self.encrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8)) : Array(UInt8)
    def self.decrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8)) : Array(UInt8)
  end

  module Padding
    def self.pkcs7(buffer : Indexable(UInt8), block_size : Int)
  end
end
```

## Usage

### IGE Mode

**Note:** Data must be padded to match a multiple of the block size `AES::BLOCK_SIZE`.

```crystal
require "tgcrypto"

random = Random.new

# 10 MB of random data + 7 bytes to show padding
data = random.random_bytes(10 * 1024 * 1024 + 7)

key = random.random_bytes(32) # Random key
iv = random.random_bytes(32) # Random iv

# Pad the data using PKCS7
data = TGCrypto::Padding.pkcs7(data, TGCrypto::AES::BLOCK_SIZE)

encrypted = TGCrypto::IGE.encrypt(data, key, iv)
decrypted = TGCrypto::IGE.decrypt(encrypted, key, iv)

puts data == decrypted
# => true
```

### CTR Mode

```crystal
require "tgcrypto"

random = Random.new

# 10 MB of random data + 7 bytes to show padding
data = random.random_bytes(10 * 1024 * 1024 + 7)

key = random.random_bytes(32) # Random key
iv = random.random_bytes(16) # Random iv

# Pad the data using PKCS7
data = TGCrypto::Padding.pkcs7(data, TGCrypto::AES::BLOCK_SIZE)

encrypted = TGCrypto::CTR.xcrypt(data, key, iv)
decrypted = TGCrypto::CTR.xcrypt(encrypted, key, iv)

puts data == decrypted
```

### CBC Mode

**Note:** Data must be padded to match a multiple of the block size `AES::BLOCK_SIZE`.

```crystal
require "tgcrypto"

random = Random.new

# 10 MB of random data + 7 bytes to show padding
data = random.random_bytes(10 * 1024 * 1024 + 7)

key = random.random_bytes(32) # Random key
iv = random.random_bytes(16) # Random iv

# Pad the data using PKCS7
data = TGCrypto::Padding.pkcs7(data, TGCrypto::AES::BLOCK_SIZE)

encrypted = TGCrypto::CBC.encrypt(data, key, iv)
decrypted = TGCrypto::CBC.decrypt(encrypted, key, iv)

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
  - [ ] CTR256
    - [ ] 128
    - [ ] 192
    - [x] 256
  - [ ] IGE256
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

1. Fork it (<https://github.com/watzon/tgcrypto/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Chris Watson](https://github.com/watzon) - creator and maintainer
