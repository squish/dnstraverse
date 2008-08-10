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

module DNSTraverse
  
  class Response::NoGlue < Response
    
    attr_reader :qname, :qclass, :qtype, :ip, :bailiwick, :server
    
    def initialize(args)
      # we queried @ip about @qname/@qclass/@qtype and received @server as a
      # referral in bailiwick @bailiwick but without any glue
      @qname = args[:qname]
      @qclass = args[:qclass]
      @qtype = args[:qtype]
      @bailiwick = args[:bailiwick]
      @ip = args[:ip]
      @server = args[:server]
      @decoded_query = nil
      @infocache = nil
      @starters = nil
      @starters_bailiwick = nil
      @status = :noglue
      update_stats_key
      return self
    end
    
    def method_missing(key, *args, &block)
      super # there are no missing methods, we answer directly
    end
    
    def update_stats_key
      @stats_key = "key:#{@ip}:#{@status}:#{@qname}:#{@qclass}:#{@qtype}:#{@server}:#{@bailiwick}"
    end
    
    def to_s
      return "No glue for #{@server}"
    end
    
  end
  
end