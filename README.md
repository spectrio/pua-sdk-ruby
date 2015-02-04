Pop Up Archive Ruby Client SDK
=========================================

Ruby client SDK for popuparchive.com.

OAuth credentials are available from https://www.popuparchive.com/oauth/applications

Example:

```ruby
require 'popuparchive'

# create a client
pua_client = PopUpArchive::Client.new(
  :id     => 'oauth_id',
  :secret => 'oauth_secret',
  :host   => 'https://www.popuparchive.com/'
  :debug  => false
)

# fetch a collection
resp = pua_client.get('/collection/1234')

# or idiomatically
collection = pua_client.get_collection('1234')
items      = pua_client.get_items(1234)  # all items for collection

# specific item (collection_id, item_id)
item = pua_client.get_item(1234, 5678)
