require 'Dnsruby'

require 'log'

module DNSCheck
  class CachingResolver < Dnsruby::Resolver
    def initialize(*args)
      @cache = Hash.new
      super(*args)
    end
    def query(name, type, klass = Dnsruby::Classes.IN)
      ip = self.config.nameserver[0]
      Log.debug { "Querying #{name} to #{ip} class #{klass} type #{type}"}
      key = "#{ip}:#{name}:#{klass}:#{type}"
      if @cache.has_key?(key) then
        Log.debug { "Cache hit: #{key}" }
        return @cache[key]
      end
      msg = Dnsruby::Message.new
      msg.add_question(name, type, klass)
      q = Queue.new
      send_async(msg, q)
      id, result, error = q.pop
      @cache[key] = result
      Log.debug { "Cache store: #{key}" }
      @cache[key]
    end
  end

end
