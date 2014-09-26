Pop Up Archive Ruby Client SDK
=========================================

Ruby client SDK for popuparchive.com.

Example:

```ruby
require 'popuparchive'

# create a client
pua_client = PopUpArchiveClient.new(
  :id     => 'oauth_id',
  :secret => 'oauth_secret',
  :host   => 'https://www.popuparchive.com/'
  :debug  => false
)

# fetch a collection
resp = pua_client.get('/collection/1234')
# or idiomatically
collection = pua_client.get_collection('1234')


