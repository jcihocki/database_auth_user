module StartupGiraffe
  module DatabaseAuthUser
    def self.included base
      require 'bcrypt'
      require 'hmac-sha2'

      base.field :username, type: String
      base.field :password_hash, type: String

      base.scope :by_username, ->( username ) { base.where( username: username ) }
      base.index( { username: 1 }, { sparse: true, unique: true } )
      base.attr_protected :password_hash

      class << base
        attr_accessor :auth_cookie_name
        attr_accessor :system_wide_salt
      end
      base.auth_cookie_name = "auth"
      base.system_wide_salt = ""


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
      def authenticate( username, password, ctlr = nil, expires = nil )
        user = self.by_username( username ).first
        if user
          if BCrypt::Password.new( user.password_hash ) != password || !user.can_login?
            user = nil
          elsif ctlr
            auth_cookie_val = user.create_auth_cookie
            ctlr.cookies[self.auth_cookie_name] = { :value => auth_cookie_val, :expires => expires } if expires
            ctlr.cookies[self.auth_cookie_name] = auth_cookie_val unless expires
          end
        end
        return user
      end

      def check_database_user_auth( ctlr )
        cookie_val = ctlr.cookies[self.auth_cookie_name]
        if cookie_val
          begin
            auth_hash = JSON.parse( Base64.decode64( "#{cookie_val.tr( '-_', '+/' )}==" ) )
            candidate = find( auth_hash['payload'] )
            if candidate.auth_signature( auth_hash['modulus'] ) == auth_hash['signature']
              return candidate
            end
          rescue
            # Log something?
          end
        end
        return nil
      end
    end

    def create_auth_cookie
      modulus = rand( 100000000 ).to_s
      return Base64.encode64( { "payload" => self.id.to_s, "modulus" => modulus, "signature" => auth_signature( modulus ) }.to_json ).strip.tr( '+/', '-_' ).gsub( /[\n\r=]/, '' )
    end

    def auth_signature modulus
      HMAC::SHA256.hexdigest( self.class.system_wide_salt, "#{modulus}#{self.id.to_s}#{self.password_hash}" )
    end

    def can_login?
      true
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