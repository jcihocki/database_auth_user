require '../spec_helper'

describe StartupGiraffe::DatabaseAuthUser do
  before {
    User.create_indexes
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
  end
end