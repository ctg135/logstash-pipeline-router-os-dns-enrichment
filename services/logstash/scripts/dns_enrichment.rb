require 'dalli'

def filter(event)
    cache = Dalli::Client.new('memcached:11211')
    # Key - is destination IP
    key = event.get('[destination][ip]')
    # Value - id DNS by IP
    value = cache.get(key)

    if value
        event.set('[destination][dns]', value)
        tags = event.get('[tags]')
        tags << 'enriched'
        event.set('[tags]', tags)
    end

    return [event]
end
