module StartupGiraffe
  module DatabaseAuthUser
    def self.included base
      require 'bcrypt'

      base.field :username, type: String
      base.field :password_hash, type: String

      base.scope :by_username, ->( username ) { base.where( username: username ) }
      base.index( { username: 1 }, { sparse: true, unique: true } )
      base.attr_protected :password_hash

      base.validate :password do
        unless self.username.blank?
          if self.password_hash.blank?
            errors.add( :password, "is required" )
          elsif @password_error
            errors.add( :password, @password_error )
          end
        end
      end
      base.validates_uniqueness_of :username, :unless => ->() { self.username.blank? }

      base.extend ClassMethods
    end

    module ClassMethods
      def authenticate( username, password )
        user = self.by_username( username ).first
        if user
          if BCrypt::Password.new( user.password_hash ) != password
            user = nil
          end
        end
        return user
      end
    end

    def password
      ""
    end

    def password=  str
      if !str.nil?
        if str.size >= 8
          self.password_hash = BCrypt::Password.create( str )
          @password_error = nil
        else
          @password_error = "must be at least 8 characters"
        end
      else
        @password_error = "is required"
      end
    end
  end
end