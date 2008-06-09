require 'Dnsruby'
require 'logger'
require 'log'

class DNSCheck
  def initialize(args)
    Log.level = args[:loglevel] if args[:loglevel]
    Log.debug { "Initialize with args: " + args.inspect }
    @state = args[:state] || nil
    @progress = args[:progress] || nil
    tcp = args[:tcp] || false
    retries = args[:retries] || 2
    retry_delay = args[:retry_delay] || 2
    dnssec = args[:dnssec] || false
    srcaddr = args[:srcaddr] || :'0.0.0.0'
    rescfg = Dnsruby::Config.new
    rescfg.apply_domain = false
    rescfg.apply_search_list = false
    resargs = { :config_info => rescfg, :use_tcp => tcp, :recurse => false,
      :retry_times => retries, :retry_delay => retry_delay, :dnssec => dnssec,
      :ignore_truncation => false, :src_address => srcaddr }
    Log.debug { "Creating remote resolver object"}
    @resolver = Dnsruby::Resolver.new(resargs) # used for set nameservers
    Log.debug { "Creating local resolver object"}
    @lresolver = Dnsruby::Resolver.new(resargs) # left on local default
    self
  end
  def run
    Log.debug { "run entry" }
    @progress.call(:state => @state, :node => :test)
    Log.debug { "run exit" }
  end
  def get_a_root(args)
    aaaa = args[:aaaa] || false
    Log.debug { "get_a_root entry" }
    response = @lresolver.query('www.google.com', aaaa ? Dnsruby::Types.AAAA : Dnsruby::Types.A)
    Log.debug { "get_a_root exit" }
  end
  def find_roots(args)
    initial = args[:initial] || :localhost
    aaaa = args[:aaaa] || false
    Log.debug { "find_roots entry" }
    @resolver.set_config_nameserver(initial)
    response = @resolver.query('', aaaa ? Dnsruby::Types.AAAA : Dnsruby::Types.A)
    pp response
    Log.debug { "find_roots exit" }
  end
end