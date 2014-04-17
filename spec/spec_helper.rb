$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), "..", "lib"))

require "rspec"
require "startup_giraffe/database_auth_user"
require "factory_girl"
require "mongoid"
require 'active_model'
require 'protected_attributes'

# Set the database that the spec suite connects to.
Mongoid.configure do |config|
  config.connect_to("database_auth_user_test", read: :primary)
end

FactoryGirl.definition_file_paths << File.expand_path("../factories", __FILE__)
FactoryGirl.find_definitions

RSpec.configure do |config|
  config.order = "random"
  
  # Drop all collections and clear the identity map before each spec.
  config.before(:each) do
    Mongoid.purge!
  end
end


