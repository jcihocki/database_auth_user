require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe StartupGiraffe::DatabaseAuthUser do
  before {
    User.create_indexes
    User.auth_cookie_name = "auth"
  }

  it "doesn't allow inclusion in a non mongoid doc" do
    expect {
      NonDocUser.send( :include, StartupGiraffe::DatabaseAuthUser )
    }.to raise_error
  end

  it "doesn't allow mass assigning password hash" do
    User.new( username: "yerpderp", password_hash: "raaaaa" ).password_hash.should be_nil
  end

  context "when registering" do
    context "with a username" do
      context "that is already registered" do
        before {
          @user1 = User.create!( username: "foobarbaz", password: "greatpassword" )
        }

        it "is invalid" do
          User.new( username: "foobarbaz", password: "greatpassword2" ).should be_invalid
        end
      end

      it "requires a username" do

      end

      it "requires a password" do
        User.new( username: "foobarbaz", password: "" ).should be_invalid
      end

      it "requires a password longer than 7 chars" do
        User.new( username: "foobarbaz", password: "1234567" ).should be_invalid
      end

      it "doesn't store plain text passwords" do
        User.new( username: "foobarbaz", password: "12345678" ).password_hash.should_not == "12345678"
      end

      it "doesn't allow retrieval of passwords" do
        User.new( username: "foobarbaz", password: "12345678" ).password.should be_blank
      end

      it "stores different hashes for the same password" do
        user1 = User.new( username: "foobarbaz", password: "12345678" )
        user2 = User.new( username: "foobarbaz2", password: "12345678" )
        user1.password_hash.should_not == user2.password_hash
      end
    end

    context "without a username" do
      it "doesn't require a password" do
        User.new().should be_valid
      end

      it "can save many such users" do
        expect {
          3.times { User.create! }
        }.to change { User.count }.to 3
      end
    end
  end

  context "when authenticating" do
    before {
      @user = User.create!( username: "exists", password: "passwordishly" )
    }

    context "an unregistered username" do
      it "returns nil" do
        User.authenticate( "noexisty", "passwordishly" ).should be_nil
      end
    end

    context "a registered username with the wrong password" do
      it "returns nil" do
        User.authenticate( "exists", "passwordishlizzle" ).should be_nil
      end
    end

    context "a registered username with the correct password" do
      it "returns the user" do
        User.authenticate( "exists", "passwordishly" ).should == @user
      end
    end

    context "when #can_login? starts returning false" do
      it "returns nil" do
        expect {
          @user = @user.becomes( DisabledUser ).save!
        }.to change { User.authenticate( "exists", "passwordishly" ) }.to nil
      end
    end

    describe "auth cookie" do
      before {
        @ctlr = FudgedController.new
      }

      it "should be different from previous" do
        User.authenticate( "exists", "passwordishly", @ctlr.cookies )
        cookie1 = @ctlr.cookies['auth']
        User.authenticate( "exists", "passwordishly", @ctlr.cookies )
        cookie2 = @ctlr.cookies['auth']
        cookie1.should_not == cookie2
      end

      it "contains only A-z0-9_-" do
        20.times.collect do
          User.authenticate( "exists", "passwordishly", @ctlr.cookies )
          @ctlr.cookies['auth']
        end.join.match( /^[A-z0-9_\-]+$/ ).should_not be_nil
      end

      context "when auth cookie name set to foo-auth" do
        before {
          User.auth_cookie_name = "foo-auth"
        }

        it "sets cookie with name foo-auth" do
          expect {
            User.authenticate( "exists", "passwordishly", @ctlr.cookies )
          }.to change { @ctlr.cookies['foo-auth'] }.from nil
        end
      end

      context "when expiration time defined" do
        before {
          @expires = 3.weeks.from_now
          User.authenticate( "exists", "passwordishly", @ctlr.cookies, @expires )
          @cookie = @ctlr.cookies['auth']
        }

        it "sets encoded auth string" do
          @cookie[:value].should_not be_nil
        end

        it "sets cookie with expires time" do
          @cookie[:expires].should == @expires
        end
      end
    end
  end

  context "when checking authorization" do
    before {
      User.create!( username: "exists", password: "passwordishly" )
      @ctlr = FudgedController.new
      @user = User.authenticate( "exists", "passwordishly", @ctlr.cookies )
    }

    context "if same authorization that was set" do
      it "returns the user" do
        User.check_database_user_auth( @ctlr.cookies ).should == @user
      end
    end

    context "if payload modified after being set" do
      before {
        User.system_wide_salt = "secret"
        @hash = JSON.parse( Base64.decode64( "#{@ctlr.cookies['auth'].tr( '-_', '+/' )}==" ) )
        @user2 = User.create!( username: "Numbertwo", password: "thedeuce" )
        @hash['payload'] = @user2.id.to_s
        @ctlr.cookies['auth'] = Base64.encode64( @hash.to_json ).strip.tr( '+/', '-_' ).gsub( /[\n\r=]/, '' )
      }

      after {
        User.system_wide_salt = ""
      }

      it "returns nil" do
        User.check_database_user_auth( @ctlr.cookies ).should be_nil
      end

      context "if signature hashed without knowing system wide secret" do
        before {
          @hash['signature'] = HMAC::SHA256.hexdigest( "", "#{@hash['modulus']}#{@hash['payload']}#{@user2.password_hash}" )
          @ctlr.cookies['auth'] = Base64.encode64( @hash.to_json ).strip.tr( '+/', '-_' ).gsub( /[\n\r=]/, '' )
        }

        it "returns nil" do
          User.check_database_user_auth( @ctlr.cookies ).should be_nil
        end
      end
    end
    
    describe "logged_in_user" do
      
      before {
        @ctlr = FudgedController.new
      }
      
      context "if the auth cookie is nil" do
        
        it "is nil" do
          User.logged_in_user( @ctlr.request ).should be_nil
        end
        
      end
      
      context "if the auth cookie is incorrect" do
        
        before {
          @user = User.authenticate( "exists", "passwordishly", @ctlr.cookies )
          @hash = JSON.parse( Base64.decode64( "#{@ctlr.cookies['auth'].tr( '-_', '+/' )}==" ) )
          @hash['payload'] = User.new.id.to_s
          @ctlr.cookies['auth'] = Base64.encode64( @hash.to_json ).strip.tr( '+/', '-_' ).gsub( /[\n\r=]/, '' )
        }
        
        it "is nil" do
          User.logged_in_user( @ctlr.request ).should be_nil
        end
        
      end
      
      context "if the auth cookie is correct" do
        
        before {
          @user = User.authenticate( "exists", "passwordishly", @ctlr.cookies )
        }
        
        it "is the user for whom the auth cookie matches" do
          User.logged_in_user( @ctlr.request ).should == @user
        end
        
      end
      
    end


    context "if user changes password" do
      before {
        @user.password = "newpasswordbish"
        @user.save
      }

      it "returns nil" do
        User.check_database_user_auth( @ctlr.cookies ).should be_nil
      end
    end
  end

  context "when logging out" do
    before {
      @user = User.create!( username: "exists", password: "passwordishly" )
      @ctlr = FudgedController.new
      User.authenticate( "exists", "passwordishly", @ctlr.cookies )
    }

    it "deletes the cookie" do
      expect {
        User.logout( @ctlr.cookies )
      }.to change { @ctlr.cookies['auth'] }.to nil
    end
  end

  context "when resetting password" do
    before {
      @other_user = User.create!( username: "exists2", password: "passwordishly" )
      @user = User.create!( username: "exists", password: "passwordishly" )
    }

    it "doesn't allow mass assigning password_reset_code field" do
      expect {
        @user.update_attributes( password_reset_code: "foo" )
      }.not_to change { @user.password_reset_code }
    end

    context "if forgot password never called" do
      it "doesn't reset password" do
        expect {
          User.reset_password( @user.password_reset_code, "derpderpderp" )
        }.not_to change { User.authenticate( "exists", "derpderpderp" ) }
      end

      it "returns nil" do
        User.reset_password( nil, "derpderpderp" ).should be_nil
      end

      it "returns nil" do
        User.reset_password( "", "derpderpderp" ).should be_nil
      end
    end

    context "when auth code correct" do
      before {
        @user.forgot_password
        @code = @user.password_reset_code
      }

      context "when password valid" do
        it "changes password" do
          expect {
            User.reset_password( @code, "derpderpderp" )
          }.to change { User.authenticate( "exists", "derpderpderp" ) }.to @user
        end

        it "returns the user" do
          User.reset_password( @code, "derpderpderp" ).should == @user
        end

        it "doesn't change another user's password" do
          expect {
            User.reset_password( @code, "derpderpderp" )
          }.not_to change { User.authenticate( "exists2", "derpderpderp" ) }
        end
      end

      context "if #forgot_password called again before use" do
        before {
          @user.forgot_password
        }

        it "doesn't reset password" do
          expect {
            User.reset_password( @code, "derpderpderp2" )
          }.not_to change { User.authenticate( "exists", "derpderpderp2" ) }
        end

        it "returns nil" do
            User.reset_password( @code, "derpderpderp2" ).should be_nil
        end
      end

      context "used for the second time" do
        before {
          User.reset_password( @user.password_reset_code, "derpderpderp" )
        }

        it "doesn't reset password" do
          expect {
            User.reset_password( @code, "derpderpderp2" )
          }.not_to change { User.authenticate( "exists", "derpderpderp2" ) }
        end

        it "returns nil" do
            User.reset_password( @code, "derpderpderp2" ).should be_nil
        end
      end
    end

    context "when auth code modified/incorrect" do
      before {
        @user.forgot_password
        @code = @user.password_reset_code
        @code[4] = "g"
      }

      it "doesn't reset password" do
        expect {
          User.reset_password( @code, "derpderpderp" )
        }.not_to change { User.authenticate( "exists", "derpderpderp" ) }
      end

      it "returns nil" do
        User.reset_password( nil, "derpderpderp" ).should be_nil
      end

    end

    describe "reset code" do
      before {
        @user.forgot_password
        @other_user.forgot_password

      }

      it "is different for 2 different users" do
        @user.password_reset_code.should_not == @other_user.password_reset_code
      end
    end
  end
end