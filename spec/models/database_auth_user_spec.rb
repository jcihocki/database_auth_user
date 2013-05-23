require '../spec_helper'

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
        User.authenticate( "exists", "passwordishly", @ctlr )
        cookie1 = @ctlr.cookies['auth']
        User.authenticate( "exists", "passwordishly", @ctlr )
        cookie2 = @ctlr.cookies['auth']
        cookie1.should_not == cookie2
      end

      it "contains only A-z0-9_-" do
        20.times.collect do
          User.authenticate( "exists", "passwordishly", @ctlr )
          @ctlr.cookies['auth']
        end.join.match( /^[A-z0-9_\-]+$/ ).should_not be_nil
      end

      context "when auth cookie name set to foo-auth" do
        before {
          User.auth_cookie_name = "foo-auth"
        }

        it "sets cookie with name foo-auth" do
          expect {
            User.authenticate( "exists", "passwordishly", @ctlr )
          }.to change { @ctlr.cookies['foo-auth'] }.from nil
        end
      end

      context "when expiration time defined" do
        before {
          @expires = 3.weeks.from_now
          User.authenticate( "exists", "passwordishly", @ctlr, @expires )
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
      @user = User.authenticate( "exists", "passwordishly", @ctlr )
    }

    context "if same authorization that was set" do
      it "returns the user" do
        User.check_database_user_auth( @ctlr ).should == @user
      end
    end

    context "if payload modified after being set" do
      before {
        hash = JSON.parse( Base64.decode64( "#{@ctlr.cookies['auth'].tr( '-_', '+/' )}==" ) )
        hash['payload'] = Moped::BSON::ObjectId.new.to_s
        @ctlr.cookies['auth'] = Base64.encode64( hash.to_json ).strip.tr( '+/', '-_' ).gsub( /[\n\r=]/, '' )
      }

      it "returns nil" do
        User.check_database_user_auth( @ctlr ).should be_nil
      end
    end

    context "if user changes password" do
      before {
        @user.password = "newpasswordbish"
        @user.save
      }

      it "returns nil" do
        User.check_database_user_auth( @ctlr ).should be_nil
      end
    end
  end
end