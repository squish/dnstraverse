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
require 'dnstraverse/fingerprint_rules'
require 'dnsruby'
require 'pp'

module DNSTraverse
  class Fingerprint
    include FingerprintRules
    
    FINGERPRINT_TIMEOUT = 'query timed out'.freeze
    
    attr_accessor :version_style # :none, :override, :append
    
    def initialize(args = {})
      @version_style = args[:version_style] || :append
      cfg = Dnsruby::Config.new
      rescfg = { :nameserver => cfg.nameserver, :ndots => cfg.ndots,
        :apply_domain => false, :apply_search_list => false}
      resargs = { :config_info => rescfg, :use_tcp => false, :recurse => false,
        :packet_timeout => 2, :retry_times => 1, :retry_delay => 1,
        :dnssec => false, :ignore_truncation => true, :src_address => '0.0.0.0',
        :udp_size => 512 }
      @resolver = Dnsruby::Resolver.new(resargs)
      @resolver.udp_size = 512
      #Dnsruby.log.level = Logger::DEBUG
      #Log.level = Logger::DEBUG
    end
    
    def fingerprint(ip)
      return process(ip, INITRULE[:header], INITRULE[:query], RULESET)
    end
    
    def process(ip, header, query, ruleset)
      ret = Hash.new
      answer, errstr = probe(ip, header, query)
      id = answer ? header2fp(answer.header) : errstr
      Log.debug { "query = #{query}, id = #{id}" }
      for rule in ruleset do
        raise "Missing fingerprint" unless rule.has_key?(:fingerprint)
        next unless id =~ /#{rule[:fingerprint]}/
        if rule.has_key?(:result) then
          result = rule[:result]
          if result.is_a? String
            ret[:state] = result
            ret[:error] = result
            ret[:id] = id
            return ret
          end
          for k in [:vendor, :product, :option] do
            ret[k] = result[k] if result.has_key?(k) and result[k].length > 0
          end
          case @version_style
          when :none
            ret[:version] = result[:version]
          when :append
            ver = query_version(ip, result[:qv])
            ver = query_version(ip, "version.bind") unless ver
            ret[:version] = result[:version]
            ret[:version]+= " (#{ver})" if ver
          when :override
            ver = query_version(ip, result[:qv])
            ver = query_version(ip, "version.bind") unless ver
            ret[:version] = ver ? ver : result[:version]
          end
          return ret
        end
        if rule.has_key?(:state) then
          ret[:state] = rule[:state]
          ret[:error] = "No match found"
          ret[:id] = id
          return ret
        end
        query = rule[:query] if rule.has_key?(:query)
        if rule.has_key?(:header) and rule.has_key?(:ruleset) then
          return process(ip, rule[:header], query, rule[:ruleset])
        end
        raise "Invalid ruleset -- no next step"
      end
      raise "Invalid ruleset -- fell off end"
    end
    
    def query_version(ip, name)
      @resolver.nameserver = ip
      @resolver.dnssec = false
      begin
        msg = @resolver.query(name, 'TXT', 'CH')
        if msg.answer.size > 0 then
          ver = msg.answer[0].data.sub(/[^0-9a-zA-Z. :!?-]/, '')
          return ver.length > 0 ? ver : nil
        end
      rescue Exception
        return nil
      end
    end
    
    def header2fp(header)
      list = [ header.qr, header.opcode, header.aa, header.tc, header.rd,
      header.ra, header.ad, header.cd, header.get_header_rcode, header.qdcount,
      header.ancount, header.nscount, header.arcount ]
      list.map! do | item |
        next '0' if item.instance_of? FalseClass
        next '1' if item.instance_of? TrueClass
        next "NS_NOTIFY_OP" if item == "Notify"
        item
      end
      return list.join(',').upcase
    end
    
    def fp2header(headerstr)
      list = headerstr.split(/,/)
      h = Dnsruby::Header.new
      h.qr = list.shift == '1' ? true : false
      opcode = list.shift
      opcode = "Notify" if opcode == "NS_NOTIFY_OP"
      h.opcode = opcode
      h.aa = list.shift == '1' ? true : false
      h.tc = list.shift == '1' ? true : false
      h.rd = list.shift == '1' ? true : false
      h.ra = list.shift == '1' ? true : false
      h.ad = list.shift == '1' ? true : false
      h.cd = list.shift == '1' ? true : false
      h.rcode = list.shift
      h.qdcount = list.shift.to_i
      h.ancount = list.shift.to_i
      h.nscount = list.shift.to_i
      h.arcount = list.shift.to_i
      return h
    end
    
    def decode_query(querystr)
      qname, qclass, qtype = querystr.split(/\s+/)
      if qtype == "CLASS0" then # crappy data
        qtype = qclass
        qclass = "CLASS0"
      end
      q = Dnsruby::Question.new(qname, qtype, qclass)
      return q
    end
    
    def probe(ip, headerstr, query)
      @resolver.nameserver = ip
      @resolver.dnssec = false
      msg = Dnsruby::Message.new
      msg.header = fp2header(headerstr)
      msg.add_question(decode_query(query))
      result, error = @resolver.send_plain_message(msg)
      ans = result || error
      return nil, FINGERPRINT_TIMEOUT if ans.is_a? Dnsruby::ResolvTimeout
      return nil, ans.to_s if ans.is_a? Exception
      return ans, nil
    end
    
  end
  
end
