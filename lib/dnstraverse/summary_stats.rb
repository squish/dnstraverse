module DNSTraverse
  class SummaryStats

    def initialize(referral)
      @summary_stats = get_summary_stats(referral)
      @answer_stats = get_answer_stats(referral)
    end

    # summary returns a hash summarising the results
    #
    # the key is the type of result, e.g.:
    #   :exception, :noglue, :nodata, :answered, etc.
    # the value is a hash containing:
    #   :prob #=> probability of getting this result
    # all probabilities will add up to 1
    #
    # for example
    # {
    #   :exception => { :prob => 0.5 },
    #   :answered => { :prob => 0.5 }
    # }
    def summary
      @summary_stats
    end

    # each_summary takes a block and yields the type and summary info
    #
    # for example
    # stats.each_summary do |type, sinfo|
    #   puts "#{prob} = #{sinfo[:prob]}"
    # end
    def each_summary
      @summary_stats.each_pair do |type, sinfo|
        yield type, sinfo
      end
    end

    # answers returns a hash summarising the answers referred to
    # by the key :answered in the summary statistics
    # 
    # the key is the rdata string (e.g. 192.168.0.1)
    # the value is a hash containing:
    #   :prob #=> probability of getting this result
    #   :rrs #=> array of Dnsruby::RR records
    # all probabilities add up to the chance of getting an answer
    #   (e.g. get_summary_stats()[:answered][:prob] )
    #
    # for example
    # {
    #   '192.168.0.1' => { :prob => 0.2, :rrs => [...] },
    #   '192.168.0.2' => { :prob => 0.3, :rrs => [...] }
    # }
    def answers
      @answer_stats
    end

    # each_answer takes a block and yields the probability and RR array
    #
    # for example
    # stats.each_answer do |prob, records|
    #   puts "#{prob} = #{records.join(',')}"
    # end
    def each_answer
      @answer_stats.each_pair do |type, ainfo|
        yield ainfo[:prob], ainfo[:rr]
      end
    end

    def text(args = {})
      prefix = args[:prefix] || '  '
      indent = args[:indent] || "#{prefix}          "
      o = ''
      each_summary do |type, sinfo|
        if type == :answered then
          each_answer do |prob, records|
            initial = "#{prefix}#{txt_prob prob} answered with "
            rr_prefix = "\n" + (' ' * initial.length)
            o << initial
            o << records.map {|x| x.to_s.gsub(/\s+/, ' ') }.join(rr_prefix) + "\n"
          end
        end
      end
      each_summary do |type, sinfo|
        if type != :answered then
          case type
          when :nodata
            o << "#{prefix}#{txt_prob sinfo[:prob]} found no such record"
          when :referral_lame
            o << "#{prefix}#{txt_prob sinfo[:prob]} resulted in a lame referral"
          when :exception
            o << "#{prefix}#{txt_prob sinfo[:prob]} resulted in an exception"
          when :error
            o << "#{prefix}#{txt_prob sinfo[:prob]} resulted in an error"
          when :noglue
            o << "#{prefix}#{txt_prob sinfo[:prob]} found no glue"
          when :loop
            o << "#{prefix}#{txt_prob sinfo[:prob]} resulted in a loop"
          when :cname_loop
            o << "#{prefix}#{txt_prob sinfo[:prob]} resulted in a CNAME loop"
          else
            o << "#{prefix}#{txt_prob sinfo[:prob]} #{type}"
          end
          o << "\n"
        end
      end
      return o
    end

    private
    def get_summary_stats(referral)
      s = {}
      referral.stats.each_pair do |key, data|
        response = data[:response]
        type = response.status
        s[type]||= { :prob => 0.0 }
        s[type][:prob]+= data[:prob]
      end
      return s
    end

    def get_answer_stats(referral)
      a = {}
      referral.stats.each_pair do |key, data|
        response = data[:response]
        if response.status == :answered then
          key = response.answers.map {|rr| rr.rdata_to_string }.sort.join("@@@")
          a[key]||= { :prob => 0.0, :rr => response.answers }
          a[key][:prob]+= data[:prob]
        end
      end
      return a
    end

    def txt_prob(prob)
      t = sprintf("%.1f%%", prob * 100).sub(/\.0%/, '%')
      return sprintf("%5s", t) # 99.9%
    end

  end
end
