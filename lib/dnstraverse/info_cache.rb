#    DNSTraverse traverses the DNS to show statistics and information
#    Copyright (C) 2008 James Ponder
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'dnstraverse/log'

module DNSTraverse
  class InfoCache
    
    attr_reader :parent
    
    private
    
    def key(rr)
      return "#{rr.name}:#{rr.klass}:#{rr.type}".downcase
    end
    
    public

    def initialize(parent = nil)
      @parent = parent
      @data = Hash.new
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
      if @data.has_key?(gkey) then
        Log.debug { "Infocache recall: " + @data[gkey].join(', ')}
        return @data[gkey] # returns Array
      end
      return nil unless parent
      return parent.get?(args)
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
    
    def get_startservers(domain, nsatype = 'A')
      Log.debug { "Getting startservers for #{domain}/#{nsatype}" }
      newbailiwick = nil
      # search for best NS records in authority cache based on this domain name
      ns = get_ns?(domain)
      starters = Array.new
      # look up in additional cache corresponding IP addresses if we know them
      for rr in ns do
        nameserver = rr.domainname.to_s
        iprrs = get?(:qname => nameserver, :qtype => nsatype)
        ips = iprrs ? iprrs.map {|iprr| iprr.address.to_s } : nil
        starters.push({ :name => nameserver, :ips => ips })
      end
      newbailiwick = ns[0].name.to_s
      Log.debug { "For domain #{domain} using start servers: " +
        starters.map { |x| x[:name] }.join(', ') }
      return starters, newbailiwick
    end

  end
end
