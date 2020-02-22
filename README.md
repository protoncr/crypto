# TGCrypto

Pure Crystal implementations of various Cryptography algorithms, made especially for use with [Proton](https://github.com/watzon/proton).

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     tgcrypto:
       github: watzon/tgcrypto
   ```

2. Run `shards install`

## Usage

```crystal
require "tgcrypto"
```

## Roadmap

- [x] AES256
- [ ] CBC256
- [ ] CTR256
- [ ] IGE256
- [ ] More?

## Contributing

1. Fork it (<https://github.com/watzon/tgcrypto/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Chris Watson](https://github.com/watzon) - creator and maintainer
