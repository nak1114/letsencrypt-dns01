# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'letsencrypt/dns01/version'

Gem::Specification.new do |spec|
  spec.name          = "letsencrypt-dns01"
  spec.version       = Letsencrypt::Dns01::VERSION
  spec.authors       = ["nak1114"]
  spec.email         = ["naktak1114@gmail.com"]

  spec.summary       = %q{Let's Encrypt DNS challenge.}
  spec.description   = %q{This gem can automate certificate issuance from Let's Encrypt with DNS challenge.}
  spec.homepage      = "https://github.com/nak1114/rbenv-win/ruby-letsencrypt-dns01"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    #spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'acme-client', '>= 0.5.0'
  #spec.add_runtime_dependency 'thor', '>= 0.19.4'
  #spec.add_runtime_dependency 'clockwork', '>= 2.0.0'

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  #spec.add_development_dependency 'vcr', "~> 3.0"
  #spec.add_development_dependency 'webmock', "~> 1.24"
  spec.add_development_dependency 'fakefs', "~> 0.10"
  spec.add_development_dependency 'pry', "~> 0.10"
  spec.add_development_dependency 'simplecov', "~> 0.13"
end
