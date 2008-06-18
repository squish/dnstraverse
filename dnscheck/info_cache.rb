require 'Log'

module DNSCheck
  class InfoCache
    
    attr_reader :data # hash (string keys, see key() )
    
    private
    
    def key(rr)
      return "#{rr.name}:#{rr.klass}:#{rr.type}".downcase
    end
    
    public
    
    def initialize(initobj = nil)
      if initobj.is_a? InfoCache then
        @data = initobj.data.dup
      else
        @data = Hash.new
      end
      self
    end
    
    def add(rrs)
      rrs.each {|rr| @data[key(rr)] = Array.new } # clear out
      for rr in rrs do
        @data[key(rr)].push rr
        Log.debug { "Adding to infocache: #{rr}" }
      end
      return nil
    end
    
    def get?(args)
      qclass = args[:qclass] || 'IN'
      gkey = "#{args[:qname]}:#{qclass}:#{args[:qtype]}".downcase
      return nil unless @data.has_key?(gkey)
      Log.debug { "Infocache recall: " + @data[gkey].join(', ')}
      return @data[gkey] # returns Array
    end
    
    def get_ns?(domain) # get an appropriate ns based on domain
      domain = domain.to_s
      while true do
        Log.debug { "get_ns? checking #{domain}" }
        rrs = get?(:qname => domain, :qtype => 'NS')
        return rrs if rrs
        return false unless i = domain.index('.')
        domain = domain[i+1..-1]
      end
    end
  end
end
