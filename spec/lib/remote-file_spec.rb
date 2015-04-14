require 'spec_helper'

describe PopUpArchive::Client do
  it "should initialize sanely" do
    client = get_pua_client
  end

  it "should fetch root endpoint" do
    client = get_pua_client
    resp = client.get('/')
    #puts pp( resp )
  end

end

describe "should add Item to Collection" do
  it "should add Item" do
    client = get_pua_client
    resp = client.get('/collections')
    #puts pp( resp )
    # use the first collection, whatever it is.
    coll = resp.collections.first
    pp coll
    item = client.create_item(coll, {
      title: 'this is an item with remote audio files'
    })
    pp item
    remote_audio = 'https://speechmatics.com/api-samples/zero'
    audio_file = client.create_audio_file(item, {
      remote_file_url: remote_audio
    })
    pp audio_file

    # now test that the item+audio exists
    pua_item = client.get_item(coll.id, item.id)
    expect(pua_item.title).to eq item.title
    expect(pua_item.audio_files.first.original).to eq remote_audio

  end

end

