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

# fetch a collection with id 1234
resp = pua_client.get('/collections/1234')

# or idiomatically
collection = pua_client.get_collection('1234')

# fetch a specific item (collection_id, item_id)
item = pua_client.get_item(1234, 5678)

# create a new Item
new_item = pua_client.create_item(collection, {
  title: 'this is a new Item'
})

# add an Audio File
audio_file = pua_client.create_audio_file(new_item, {
  remote_file_url: 'http://someplace/there/is/a/file.mp3'
})

```

## Development

To run the Rspec tests, create a **.env** file in the checkout
with the following environment variables set to meaningful values:

```
PUA_ID=somestring
PUA_SECRET=sekritstring
PUA_HOST=http://pop-up-archive.dev
```
