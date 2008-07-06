require 'dnsruby'
require 'dnsruby/TheLog'

require 'info_cache'
require 'log'
require 'message_utility'
require 'caching_resolver'
require 'referral'

# TODO calculations

module DNSCheck
  
  class Resolver
    include MessageUtility
    
    def progress_null(args)
    end
    
    def initialize(args)
      Log.level = args[:loglevel] if args[:loglevel]
      Log.debug { "Initialize with args: " + args.inspect }
      Dnsruby::TheLog.level = args[:libloglevel] if args[:libloglevel]
      @state = args[:state] || nil
      @progress_main = args[:progress_main] || method(:progress_null)
      @progress_resolve = args[:progress_resolve] || method(:progress_null)
      retries = args[:retries] || 2
      retry_delay = args[:retry_delay] || 2
      retries = 1
      retry_delay = 1
      dnssec = args[:dnssec] || false
      srcaddr = args[:srcaddr] || :'0.0.0.0'
      use_tcp = args[:always_tcp] || false
      ignore_truncation = args[:allow_tcp] ? false : true
      cfg = Dnsruby::Config.new
      rescfg = { :nameserver => cfg.nameserver, :ndots => cfg.ndots,
        :apply_domain => false, :apply_search_list => false}
      resargs = { :config_info => rescfg, :use_tcp => use_tcp, :recurse => false,
        :retry_times => retries, :retry_delay => retry_delay, :dnssec => dnssec,
        :ignore_truncation => ignore_truncation, :src_address => srcaddr }
      Log.debug { "Creating remote resolver object"}
      @resolver = CachingResolver.new(resargs) # used for set nameservers
      @resolver.udp_size = Dnsruby::Resolver::DefaultUDPSize # bug in Dnsruby
      Log.debug { "Creating local resolver object"}
      @lresolver = Dnsruby::Resolver.new(resargs) # left on local default
      @lresolver.udp_size = Dnsruby::Resolver::DefaultUDPSize # bug in Dnsruby
      self
    end
    
    ### change to get_all or something?
    def get_a_root(args)
      aaaa = args[:aaaa] || false
      Log.debug { "get_a_root entry" }
      # get nameservers for root
      begin
        msg = @lresolver.query('', 'NS')
      rescue e
        puts "Failed to get roots, local resolver returned exception: #{e}"
        raise e
      end
      msg_validate(msg, :qname => '', :qtype => 'NS')
      msg_comment(msg, :want_recursion => true)
      ans1 = msg_answers?(msg, :qname => '', :qtype => 'NS')
      unless ans1 then
        raise ResolveError, "No root nameservers found: " + e.to_str
      end
      roots = ans1.map {|x| x.domainname.to_s }
      Log.debug { "Local resolver lists: " + roots.join(', ') }
      types = aaaa ? ['AAAA'] : []
      types.push 'A'
      # loop through all root nameservers to get an appropriate address
      for root in roots do
        # lets check additional section first
        for type in types do
          if (add = msg_additional?(msg, :qname => root, :qtype => type)) then
            rootip = add[0].rdata.to_s
            return root, rootip
          end
        end
      end
      Log.debug { "Nothing in additional section of help" }
      for root in roots do
        for type in types do
          Log.debug { "Resolving root #{root} type #{type}" }
          msg = @lresolver.query(root, type)
          msg_validate(msg, :qname => root, :qtype => type)
          msg_comment(msg, :want_recursion => true)
          ans2 = msg_answers?(msg, :qname => root, :qtype => type)
          if ans2 then
            rootip = ans2[0].rdata.to_s # use first one
            Log.debug { "get_a_root exit: #{root} #{rootip}" }
            return root, rootip
          end
          Log.debug { "#{root}/#{type}: No suitable answers found" }
        end
        # there was no appropriate answer for this root
      end
      raise ResolveError, "No address could be found for any root server"
    end
    
    def run(r)
      Log.debug { "run entry, initialising stack to: " + r.to_s }
      stack = Array.new
      stack << r
      while stack.size > 0 do
        Log.debug { "stack size is #{stack.size}" }
        Log.debug {
          counter = 0
          output = ""
          for entry in stack.reverse do
            output+= sprintf "%04d %s\n", counter, entry.to_s
            counter+= 1
          end
          output
        }
        raise "bad stack" if stack.size > 100
        r = stack.pop
        Log.debug { "running on stack entry #{r}" }
        case r
          when :calc_resolve
          r = stack.pop
          refres = r.referral_resolution?
          p = (refres == true ? @progress_resolve : @progress_main)
          p.call(:state => @state, :referral => r, :answer => true)
          r.resolve_calculate
          stack << r # now need to process
          next
          when :calc_answer
          r = stack.pop
          refres = r.referral_resolution?
          p = (refres == true ? @progress_resolve : @progress_main)
          p.call(:state => @state, :referral => r, :answer => true)
          r.answer_calculate
          next
        else
          refres = r.referral_resolution?
          p = (refres == true ? @progress_resolve : @progress_main)
          p.call(:state => @state, :referral => r, :answer => false)
        end
        unless r.resolved? then
          # get resolve Referral objects, place on stack with placeholder
          stack << r << :calc_resolve
          stack.push(*r.resolve({}).reverse)
          next
        end
        unless r.processed? then
          # get Referral objects, place on stack with placeholder
          stack << r << :calc_answer
          stack.push(*r.process({}).reverse)
          next
        end
        if stack.size == 0 then
          puts "All done!!!"
        end
        raise "Fatal stack error at #{r} - size still #{stack.size}"
      end
    end
    
    #    def find_all_roots(args)
    #      root = args[:root] || 'localhost'
    #      rootip = args[:rootip] || '127.0.0.1'
    #      aaaa = args[:aaaa] || false
    #      Log.debug { "find_roots entry #{root}" }
    #      # use our initial root to find all the roots
    #      r = Referral.new(:refid => '0', :server => nil,
    #      :qname => '', :qtype => 'NS', :nsatype => aaaa ? 'AAAA' : 'A',
    #      :roots => [ { :name => root, :ips => [rootip] } ],
    #      :resolver => @resolver)
    #      run(r)
    #      Log.debug { "find_roots exit" }
    #    end
    
    # asks the :root/:rootip server for all the roots, fills in any missing
    # IP addresses from local resolver
    def find_all_roots(args)
      root = args[:root] || 'localhost'
      rootip = args[:rootip] || '127.0.0.1'
      aaaa = args[:aaaa] || false
      qtype = aaaa ? 'AAAA' : 'A'
      Log.debug { "find_roots entry #{root}" }
      @resolver.nameserver = rootip
      @resolver.udp_size = Dnsruby::Resolver::DefaultUDPSize # bug in Dnsruby
      msg = @resolver.query('', 'NS')
      msg_validate(msg, :qname => '', :qtype => 'NS')
      msg_comment(msg, :want_recursion => false)
      ns = msg_answers?(msg, :qname => '', :qtype => 'NS')
      return nil unless ns
      roots = Array.new
      for rr in ns do
        iprrs = msg_additional?(msg, :qname => rr.domainname, :qtype => qtype)
        ips = iprrs ? iprrs.map {|iprr| iprr.address.to_s } : nil
        unless ips then
          Log.debug { "Locally resolving root #{rr.domainname} type #{qtype}" }
          msg = @lresolver.query(rr.domainname, qtype)
          msg_validate(msg, :qname => rr.domainname, :qtype => qtype)
          msg_comment(msg, :want_recursion => true)
          ans = msg_answers?(msg, :qname => rr.domainname, :qtype => qtype)
          unless ans then
            Log.warn { "Failed to resolve #{rr.domainname} type #{qtype}" }
            next
          end
          ips = ans.map { |x| x.address.to_s }
        end
        roots.push({ :name => rr.domainname, :ips => ips })
      end
      Log.debug { "find_roots exit, #{roots.map { |x| x[:name] }.join(', ') }" }
      return roots
    end
    
    def run_query(args)
      qname = args[:qname]
      qtype = args[:qtype] || 'A'
      Log.debug { "run_query entry qname=#{qname} qtype=#{qtype}" }
      r = Referral.new(:qname => qname, :qtype => qtype, :roots => args[:roots],
                       :resolver => @resolver, :nsatype => 'A')
      run(r)
      Log.debug { "run_query exit" }
      return r
    end
  end
  
end