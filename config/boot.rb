require 'bundler'

Bundler.require(*[:default, ENV.fetch('RACK_ENV') { 'development' }])

require 'json'
