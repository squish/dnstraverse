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

require 'dnsruby'

require 'dnstraverse/log'

module DNSTraverse
  
  class CachingResolver < Dnsruby::Resolver
    
    attr_reader :requests, :cache_hits
    
    def initialize(*args)
      @cache = Hash.new
      @requests = 0
      @cache_hits = 0
      super(*args)
    end
    
    def query(name, type, klass = Dnsruby::Classes.IN)
      @requests+= 1
      ip = self.config.nameserver[0]
      udp_size = self.udp_size
      self.udp_size = udp_size # workaround for bug in dnsruby
      Log.debug { "Querying #{name} to #{ip} class #{klass} type #{type}"}
      key = "key:res:#{ip}:#{name}:#{klass}:#{type}:#{udp_size}"
      if @cache.has_key?(key) then
        Log.debug { "Cache hit: #{key}" }
        @cache_hits+= 1
        return @cache[key]
      end
      answer = nil
      begin
        msg = Dnsruby::Message.new
        msg.add_question(name, type, klass)
        q = Queue.new
        send_async(msg, q)
        id, result, error = q.pop
        answer = result || error
      rescue => e
        answer = RuntimeError.new "Dnsruby failure: " + e.to_s
      end  
      @cache[key] = answer
      Log.debug { "Cache store: #{key}" }
      @cache[key]
    end
    
  end
  
end
