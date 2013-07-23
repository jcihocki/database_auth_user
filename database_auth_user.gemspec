# encoding: utf-8
lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)

require "startup_giraffe/database_auth_user/version"

Gem::Specification.new do |s|
  s.name        = "database_auth_user"
  s.version     = StartupGiraffe::DatabaseAuthUser::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Johnny Cihocki"]
  s.email       = ["john@startupgiraffe.com"]
  s.homepage    = "http://startupgiraffe.com"
  s.summary     = "A database password login module for mongoid models"
  s.description = "database_auth_user allows you to register and authenticate a user model based on a username and password"
  s.license     = "MIT"

  s.required_ruby_version     = ">= 1.9"
  s.required_rubygems_version = ">= 1.3.6"

  s.add_dependency("mongoid", [">= 3.0.0"])
  s.add_dependency("bcrypt")

  s.files        = Dir.glob("lib/**/*") + %w(CHANGELOG.md LICENSE README.md)
  s.require_path = 'lib'
end
