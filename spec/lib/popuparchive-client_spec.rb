require 'spec_helper'

# assumes ID and SECRET set in env vars
OAUTH_ID     = ENV['PUA_ID']
OAUTH_SECRET = ENV['PUA_SECRET']
if !OAUTH_ID or !OAUTH_SECRET
  abort("Must set PUA_ID and PUA_SECRET env vars -- did you create a .env file?")
end

def get_pua_client
  PopUpArchive::Client.new(
  :id => OAUTH_ID,
  :secret => OAUTH_SECRET,
  :host   => (ENV['PUA_HOST'] || 'http://localhost:3000'),
  :debug  => ENV['PUA_DEBUG']
  )
end

describe PopUpArchive::Client do
  it "should initialize sanely" do
    client = get_pua_client
  end

  it "should fetch root endpoint" do
    client = get_pua_client
    resp = client.get('/')
    #puts pp( resp )
  end

  it "should fetch the /users/me endpoint" do
    client = get_pua_client
    resp = client.get('/users/me')
    #puts pp( resp )
    puts "client application belongs to #{resp.name}"
  end
end

describe "collections" do
  it "should fetch collections" do
    client = get_pua_client
    resp = client.get('/collections')
    #puts pp( resp )
    expect(resp.collections).not_to be_empty
    expect(resp.collections.size).to eq(resp.collections.size)
    expect(resp.collections[0].title).to eq('My Uploads') # TODO always true?
    expect(resp.collections[0].storage).to be_truthy
  end

end

