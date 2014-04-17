module StartupGiraffe
  module DatabaseAuthUser
    def self.included base
      require 'bcrypt'
      require 'hmac-sha2'
      require 'protected_attributes'
      
      base.include ActiveModel::MassAssignmentSecurity

      base.field :username, type: String
      base.field :password_hash, type: String
      base.field :password_reset_code, type: String

      base.scope :by_username, ->( username ) { base.where( username: username ) }
      base.scope :by_password_reset_code, ->( code ) { base.where( password_reset_code: code ) }
      base.index( { username: 1 }, { sparse: true, unique: true } )
      base.index( { password_reset_code: 1 }, { sparse: true, unique: true } )
      base.attr_protected :password_hash, :password_reset_code

      class << base
        attr_accessor :auth_cookie_name
        attr_accessor :system_wide_salt
        attr_accessor :cookie_cache_attrs
      end
      base.auth_cookie_name = "auth"
      base.system_wide_salt = ""
      base.cookie_cache_attrs = [ :username ]


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
      def authenticate( username, password, cookies = nil, expires = nil )
        user = self.by_username( username ).first
        if user
          if BCrypt::Password.new( user.password_hash ) != "#{self.system_wide_salt}#{password}" || !user.can_login?
            user = nil
          elsif cookies
            auth_cookie_val = user.create_auth_cookie
            cookies[self.auth_cookie_name] = { :value => auth_cookie_val, :expires => expires } if expires
            cookies[self.auth_cookie_name] = auth_cookie_val unless expires
          end
        end
        return user
      end

      def check_database_user_auth( cookies )
        cookie_val = cookies[self.auth_cookie_name]
        if cookie_val
          begin
            auth_hash = JSON.parse( Base64.decode64( "#{cookie_val.tr( '-_', '+/' )}==" ) )
            candidate = find( auth_hash['payload'] )
            if candidate.auth_signature( auth_hash['modulus'], auth_hash['cache'] ) == auth_hash['signature']
              return candidate
            end
          rescue
            # Log something?
          end
        end
        return nil
      end

      def logout cookies
        cookies.delete( self.auth_cookie_name )
      end

      def reset_password code, new_password
        return nil if code.blank?
        user = self.by_password_reset_code( code ).first
        if user
          user.password = new_password
          user.password_reset_code = nil
          user.save
          return user
        end
        return nil
      end
      
      def logged_in_user request
        if request && request.cookies
          request[:logged_in_user] ||= check_database_user_auth request.cookies
        end
      end
      
      def cookie_cache request
        if request && request.cookies
          cookie_val = request.cookies[self.auth_cookie_name]
          return JSON.parse( JSON.parse( Base64.decode64( "#{cookie_val.tr( '-_', '+/' )}==" ) )['cache'] ) if cookie_val
        end
      end
      
      def cache_in_cookie *args
        args.each do |arg|
          self.cookie_cache_attrs << arg
        end
      end
    end

    def create_auth_cookie
      modulus = rand( 100000000 ).to_s
      cache = self.class.cookie_cache_attrs.each_with_object({}) { |attr, hash| hash[attr] = self.public_send attr }.to_json
      return Base64.encode64({
        "payload" => self.id.to_s,
        "modulus" => modulus,
        "signature" => auth_signature( modulus, cache ),
        "cache" => cache
      }.to_json ).strip.tr( '+/', '-_' ).gsub( /[\n\r=]/, '' )
    end

    def auth_signature modulus, cache
      HMAC::SHA256.hexdigest( self.class.system_wide_salt, "#{modulus}#{cache}#{self.id.to_s}#{self.password_hash}" )
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
          self.password_hash = BCrypt::Password.create( "#{self.class.system_wide_salt}#{str}" )
          @password_error = nil
        else
          @password_error = "must be at least 8 characters"
        end
      else
        @password_error = "is required"
      end
    end

    def forgot_password
      self.set password_reset_code: HMAC::SHA256.hexdigest( self.class.system_wide_salt, "#{self.id} #{Time.now.to_s} #{self.password_hash} #{BSON::ObjectId.new.to_s} #{rand( 1000000000 )}" )
    end

  end
end