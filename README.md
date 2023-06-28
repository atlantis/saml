# saml

This library is a port of ruby-saml, so for now it's targeted at Service Provider features, but eventually the goal is to target Identity Provider features as well.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     saml:
       github: atlantisnove/saml
   ```

2. Run `shards install`

## Usage

```crystal
require "saml"
```

See https://github.com/SAML-Toolkits/ruby-saml for documentation for now... since this is a close port (at the moment) it should mostly apply (just replace the `Saml` namespace with `Saml`).

## Development

TODO

## Contributing

1. Fork it (<https://github.com/atlantisnove/saml/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [atlantisnova](https://github.com/atlantisnove) - creator and maintainer
