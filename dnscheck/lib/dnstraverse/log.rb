require 'logger'

module Log
  include Logger::Severity
  
  class Formatter
    Format = "%s, [%s #%d] %5s -- %s: %s\n"
    
    def call(severity, time, progname, msg)
      #t = time.strftime("%Y-%m-%d %H:%M:%S.") << "%06d" % time.usec
      t = ""
      msg2str(msg).split(/\n/).map do |m|
        Format % [severity[0..0], t, $$, severity, progname, m]
      end
    end
    
    def msg2str(msg)
      case msg
        when ::Exception
        "#{ msg.message } (#{ msg.class })\n" <<
         (msg.backtrace || []).join("\n")
      else
        msg.to_s
      end
    end
  end
  
  def self.level=(l)
    @@logger.level = l
  end
  def self.logger=(logger)
    @@logger = logger
  end
  def self.method_missing(key, *args, &b)
    @@logger.send(key, *args, &b)
  end
  @@logger = Logger.new(STDERR)
  @@logger.formatter = Formatter.new
  @@logger.level = Logger::FATAL
end
