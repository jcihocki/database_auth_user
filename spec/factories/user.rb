require 'mongoid'

class NonDocUser

end

class User
  include Mongoid::Document
  include StartupGiraffe::DatabaseAuthUser
end

class DisabledUser < User
  def can_login?
    false
  end
end

class FudgedController
  attr_accessor :request

  def initialize
    @request = FudgedRequest.new
  end
  
  def cookies
    @request.cookies
  end
end

class FudgedRequest < Hash
  attr_accessor :cookies
  
  def initialize
    @cookies = {}
  end
  
end