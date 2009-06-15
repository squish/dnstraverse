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
require 'dnstraverse/decoded_query'

module DNSTraverse
  
  class DecodedQueryCache

    attr_reader :requests, :cache_hits, :resolver, :cache
    
    def initialize(args)
      @resolver = args[:resolver] || raise("Must pass resolver")
      @cache = Hash.new
      @requests = 0
      @cache_hits = 0
    end
    
    def query(args)
      qname = args[:qname] || raise("Must pass qname")
      qclass = args[:qclass] || raise("Must pass qclass")
      qtype = args[:qtype] || raise("Must pass qtype")
      ip = args[:ip] || raise("Must pass ip")
      bailiwick = args[:bailiwick] # could be nil
      key = "key:dqc:#{ip}:#{qname}:#{qclass}:#{qtype}:#{bailiwick}"
      Log.debug { "Decoded Query Cache query #{key}" }
      if @cache.has_key?(key) then
        Log.debug { "Decoded Query Cache hit: #{key}" }
        @cache_hits+= 1
        return @cache[key]
      end
      newargs = args.merge( { :resolver => @resolver } )
      @cache[key] = DNSTraverse::DecodedQuery.new(newargs)
      Log.debug { "Decoded Query Cache store: #{key}" }
      return @cache[key]
    end
    
  end
  
end
