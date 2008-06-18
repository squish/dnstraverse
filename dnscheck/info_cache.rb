require 'Log'

module DNSCheck
  class InfoCache
    
    attr_reader :data # hash (key is Symbol) of hashes (key is key() )
    
    private
    
    def key(rr)
      return "#{rr.name}:#{rr.klass}:#{rr.type}".downcase
    end
    
    public
    
    def initialize(initobj = nil)
      if initobj.is_a? InfoCache then
        @data = initobj.data.dup
        @data.each_pair {|k,v| @data[k] = v.dup }
      else
        @data = Hash.new
      end
      self
    end
    
    def add(rrs, args)
      store = args[:store]
      @data[store] = Hash.new unless @data.has_key?(store)
      rrs.each {|rr| @data[store][key(rr)] = Array.new } # clear out
      for rr in rrs do
        @data[store][key(rr)].push rr
        Log.debug { "Adding to infocache #{store}: #{rr}" }
      end
      return nil
    end
    
    def get?(args)
      store = args[:store]
      @data[store] = Hash.new unless @data.has_key?(store)
      qclass = args[:qclass] || 'IN'
      key = "#{args[:qname]}:#{qclass}:#{args[:qtype]}".downcase
      return nil unless @data[store].has_key?(key)
      Log.debug { "Infocache #{store} recall: " + @data[store][key].join(', ')}
      return @data[store][key] # returns Array
    end
    
    def get_ns?(args) # get an appropriate ns based on domain
      domain = args[:domain]
      while true do
        return rrs if rrs = get(:qname => domain, :qtype => 'NS',
        :store => :authority)
        return false unless i = domain.index('.')
        domain = domain[i+1, -1]
      end
    end
  end
end
