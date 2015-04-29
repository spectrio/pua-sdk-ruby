require 'spec_helper'

describe "item callback" do

  before :each do
    if !ENV['CALLBACK_URL']
      skip "set CALLBACK_URL env var to test item callback"
    end
    if !ENV['REMOTE_FILE_URL']
      skip "set REMOTE_FILE_URL env var to test item callback"
    end
  end

  it "sets CALLBACK_URL on item.extra" do

    client = get_pua_client
    resp = client.get('/collections')
    #puts pp( resp )
    # use the first collection, whatever it is.
    coll = resp.collections.first
    #pp coll
    item = client.create_item(coll, {
      title: 'this is an item with remote audio file and callback',
      extra: {
        myUUID: 'abc-123',
        callback: ENV['CALLBACK_URL'],
      }
    })
    #pp item
    audio_file = client.create_audio_file(item, {
      remote_file_url: ENV['REMOTE_FILE_URL']
    })
   
  end

end 
