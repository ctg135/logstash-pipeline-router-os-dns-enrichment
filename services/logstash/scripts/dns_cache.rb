require 'dalli'

def filter(event)
    cache = Dalli::Client.new('memcached:11211')
	# Key is IP
    key = event.get('[dns][resolved]')
    # Value is DNS
    value = event.get('[dns][query]')

    if value.is_a?(String)
        cache.set(key, value, 60) 
    end

    return [event]
end
