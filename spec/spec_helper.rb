# use local 'lib' dir in include path
$:.unshift File.dirname(__FILE__)+'/../lib'
require 'popuparchive'
require 'json'
require 'pp'
require 'dotenv'

Dotenv.load

RSpec.configure do |config|
  #config.run_all_when_everything_filtered = true
  #config.filter_run :focus
  config.color = true

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = 'random'
end

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
  # must duplicate env var because we modify it with gsub
  :host   => (ENV['PUA_HOST'] || 'http://localhost:3000').dup.to_s,
  :debug  => ENV['PUA_DEBUG'],
  #:croak_on_404 => true
  )
end
