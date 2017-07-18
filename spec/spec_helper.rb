$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require 'pp'
require 'fakefs/safe'
# require 'vcr'
# require 'webmock'
require 'simplecov'
require "letsencrypt/dns01"

SimpleCov.start

#Avoid conflict FakeFS and SimpleCov
RSpec.configure do |config|
  config.before(:suite) do
    FileUtils.rm_rf('spec/data')
    sleep 1
    FileUtils.cp_r('spec/org/','spec/data')
    #FakeFS.activate!
  end
  
  config.after(:suite) do
    #FakeFS.deactivate!
  end
end

