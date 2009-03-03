#! /usr/bin/env ruby
require 'rubygems'
require 'time'
require 'timeout'

# SnmpOid is a sortable numeric OID string
class SnmpOid
  include Comparable

  attr_reader :oidstr, :cmpstr

  def initialize(oidstr)
    @oidstr = oidstr
    @cmpstr = oidstr.split(/\./).reject {|x| x==''}.map { |x| '%08X' % x }.join(".")
  end

  def <=>(other)
    @cmpstr <=> other.cmpstr
  end

  def hash
    oidstr.hash
  end

  def eql?(other)
    oidstr == other.oidstr
  end

  def to_s
    @oidstr
  end
end

# SnmpTriple is a tuple of (SnmpOid, SNMP type, value) - sortable on SnmpOid
class SnmpTriple
  attr_reader :oid, :type, :value

  def initialize(oid, type, value)
    case type
    when /^(string|integer|unsigned|objectid|timeticks|ipaddress|counter|gauge)$/
      nil
    else
      raise "Bad SNMP type '%s'" % type
    end

    oid = SnmpOid.new(oid) unless oid.kind_of?(SnmpOid)

    @oid = oid
    @type = type
    @value = value
  end

  def <=>(other)
    @oid <=> other.oid
  end

  def to_s
    "#{@oid} = #{@type}: #{value}"
  end
  
  def value
    @value.respond_to?(:call) ? @value.call : @value
  end
end

# SnmpTripleSet represents an indexed set of SnmpTriple objects, e.g. for
# an OID sub-tree
class SnmpTripleSet
  def initialize
    @triples = []
  end

  def push(t)
    @triples.push(t)
  end

  def make_index
    @triples.sort!

    @index = {}
    @triples.each { |x| @index[x.oid] = x }
  end

  def get(oid)
    @index[oid]
  end

  def getnext(oid)
    @triples.each { |x| return x if x.oid > oid }
    nil
  end

  def triples
    @triples
  end
end

# This implements the agent end of the pass_persist protocol
class SnmpdPassPersistAgent
  def initialize(args = {}, &block)
    @in_fh = args[:in_fh] || STDIN
    @out_fh = args[:out_fh] || STDOUT
    @idle_timeout = args[:idle_timeout] || 60

    if block_given?
      @prep = block
    else
      @prep = args[:prepare_responses]
    end
    @get = args[:get]
    @getnext = args[:getnext]
  end

  def dump
    set = SnmpTripleSet.new
    @prep.call(set)
    set.make_index
    put_lines set.triples
    put_lines "."
  end

  def log(s)
  end

  def get_line
    l = Timeout::timeout(@idle_timeout) { @in_fh.gets }
    if l.nil?
      log("> <eof>")
      return nil
    end
    l.chomp!
    log("> "+l)
    l
  end

  def put_lines(s)
    s.each { |x| log("< "+x.to_s) }
    s.each { |x| @out_fh.print x.to_s+"\n" }
    @out_fh.flush
  end

  def put_triple(t)
    put_lines [ t.oid, t.type, t.value ]
  end

  def do_prepare
    set = SnmpTripleSet.new
    @prep.call(set)
    set.make_index
    set
  end

  def _do_get(oid, hook, message)
    if not hook.nil?
      triple = hook.call(oid)
    elsif not @prep.nil?
      ts = do_prepare
      triple = ts.send(message, oid)
    else
      raise "Can't " + message
    end

    if triple.nil?
      put_lines "NONE"
    else
      put_triple(triple)
    end
  end

  def do_get(oid)
    _do_get oid, @get, "get"
  end

  def do_getnext(oid)
    _do_get oid, @getnext, "getnext"
  end

  def run
    quit = false

    begin
      while not quit
        l = get_line
        break if l.nil?

        case l
          # snmpd doesn't need these commands to be
          # case-insensitive; I've made them that way for easier
          # debugging
        when /^ping$/i
          put_lines "PONG" 
        when /^get$/i
          do_get(SnmpOid.new(get_line))
        when /^getnext$/i
          do_getnext(SnmpOid.new(get_line))
        when /^set$/i
          ignore = get_line
          put_lines "not-writable"

          # Additional commands not used by snmpd
        when /^(exit|quit)$/i
          put_lines "BYE"
          quit = true
        when /^dump$/i
          dump
        else
          put_lines "unknown-command"
        end
      end
    rescue Timeout::Error
    end
  end
end