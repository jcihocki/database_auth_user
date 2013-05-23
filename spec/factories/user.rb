require 'mongoid'

class NonDocUser

end

class User
  include Mongoid::Document
  include StartupGiraffe::DatabaseAuthUser
end