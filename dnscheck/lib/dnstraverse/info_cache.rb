require 'dnstraverse/log'

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
    
    # adds the resource records, clearing out any existing entries with the
    # same details
    def add(rrs)
      rrs.each {|rr| @data[key(rr)] = Array.new } # clear out
      for rr in rrs do
        @data[key(rr)].push rr
        Log.debug { "Adding to infocache: #{rr}" }
      end
      return nil
    end
    
    # array of hashes containing :name (server name) and :ips (array of strings)
    # set domain to '' for setting root hints
    def add_hints(domain, ns)
      rrs = Array.new
      for server in ns do
        rrs.push Dnsruby::RR.create(:name => domain, :ttl => 0,
                                    :type => 'NS', :domainname => server[:name])
        for ip in server[:ips] do
          type = (ip.to_s =~ /\A(\d+)\.(\d+)\.(\d+)\.(\d+)\z/) ? 'A' : 'AAAA'
          rrs.push Dnsruby::RR.create(:type => type, :ttl => 0,
                                      :name => server[:name], :address => ip)
        end
      end
      return add(rrs)
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
        Log.debug { "Infocache get_ns? checking NS records for '#{domain}'" }
        rrs = get?(:qname => domain, :qtype => 'NS')
        return rrs if rrs
        if domain == '' then
          raise "No nameservers available for #{domain} -- no root hints set??"
        end
        domain = (i = domain.index('.')) ? domain[i+1..-1] : ''
      end
    end
  end
end
