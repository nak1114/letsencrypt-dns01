# Letsencrypt::Dns01

## Usage


make core.rb(below).and add `00 1 * * * nsd ruby core.rb` to your corntab file
```
  Letsencrypt::Dns01::BIND9.new({
    name: 'example.com',
    zonefile: '/etc/nsd/example.com.zone',
    nameserver: [ '203.0.113.0' ],
    domains: [
      'example.com',
      'www.example.com' 
    ],
    authkey: '/acme/authkey/example.com.pem',
    certdir: '/acme/example.com',
    logfile: '/var/log/letsencrypt_example.com.log',
    commands: [
       'service nsd restart',
       #'nginx -s reload',
    ],
    endpoint: 'https://acme-staging.api.letsencrypt.org',
    mail: 'hogehoge@hotmail.com',
  }).update()
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bundle exec rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nak1114/letsencrypt-dns01.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

