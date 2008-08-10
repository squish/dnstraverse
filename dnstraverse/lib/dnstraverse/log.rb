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

require 'logger'

module Log
  include Logger::Severity
  
  class Formatter
    Format = "%s, [%s #%d] %5s -- %s: %s\n"
    
    def call(severity, time, progname, msg)
      t = time.strftime("%Y-%m-%d %H:%M:%S.") << "%06d" % time.usec
      #t = ""
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
