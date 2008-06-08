module DNSCheck
  require 'logger'
  require 'singleton'
  class Log
    include Singleton
    def initialize
      @@logger = Logger.new(STDOUT)
      @@logger.level = Logger::WARN
    end
    def set_logger(logger)
      @@logger = logger
    end
    def method_missing(key, *args)
      @@logger.send(symbol, *args)
    end
    alias original_respond_to? respond_to?
    def respond_to?(key)
      original_respond_to?(key) or @@logger.respond_to?(key)
    end
    log = Log.new # create us
  end
end
