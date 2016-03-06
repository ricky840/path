#!/usr/bin/env ruby

#test
#
require 'net/http'
require 'uri'
require 'resolv'
require 'ipaddr'
require 'open3'
require 'logger'
require 'optparse'

GG = "/usr/local/akamai/tools/bin/ghost_grep"
ESPRO = "/usr/local/akamai/tools/bin/es_pro"
CURL = "/usr/bin/curl"
NSH = "/usr/local/akamai/bin/nsh"
IMAGELOG = "/a/logs/web_tomcat/catalina.out"
PRAGMA = "akamai-x-cache-on, akamai-x-get-request-id"

RETRY_GHOSTGREP = 10
TIME_WINDOW = 300 #seconds
RETRY_DELAY = 9 #seconds
START_DELAY = 3 #seconds

NUMBER_OF_FIELDS_F = 58
NUMBER_OF_FIELDS_R = 75
NUMBER_OF_FIELDS_S = 59

#Network (ff/essl) default is freeflow
$server_network = "ff"

#Hash that holds forward_machine/request_id
$ip_and_reqid = Hash.new

def akamai_domain?(domain)
  lookup = %x[dig #{domain} +short].split("\n")
  lookup.each do |each|
    if each =~ /.*akamaiedge\.net\./ or each =~ /.*akamai\.net\./
      return
    end
  end
  puts "Hostname is not on Akamai"
  exit -1
end

def valid_url?(url)
  uri = URI.parse(URI.encode(url))
  if not uri.kind_of? URI::HTTP
    puts "URL is not valid"
    exit -1
  end

  if uri.kind_of? URI::HTTPS
    $server_network = "essl"
  end

  if uri.path.empty?
    uri.path = "/"
  end

  return uri
end

def print_header(obj, direction)
  puts "[#{direction}]"
  if obj.class == Net::HTTP::Get
    puts "#{obj.method} #{obj.path}"
    obj.each_capitalized do |header, value|
      puts "#{header}: #{value}"
    end
    puts "\n"
  elsif obj.class == Array
    obj.each do |header|
      puts header
    end
  else
    puts "#{obj.code} #{obj.message}"
    obj.each_capitalized do |header, value|
      puts "#{header}: #{value}"
    end
    puts "\n"
  end
end

def countDown(seconds, msg)
  seconds.downto(1) do |sec|
    $logger.info "#{msg} #{sec}"
    sleep 1
  end
end

def runCommand(cmd)
  Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
    stdin.close
    if $?.exited?
      result = stdout.read
      if cmd.include? "curl" then result = stderr.read end
      return result
    elsif not $?.exitstatus == 0
      $logger.warn "error occured while running command #{$?.exitstatus}"
    end
  end
end

def grepLogFromImageServer(reqid, server_ip)
  cmd = "#{NSH} #{server_ip} cat #{IMAGELOG} | grep #{reqid}"

  image_logs = String.new
  image_server_reqid = String.new

  $logger.info "pulling logs from the image server"

  output = runCommand(cmd)
  case output.split("\n").size
    when 0
      $logger.info "could not find any logs from image server"
    else
      $logger.info "found log, validating.."
      if output.split[7] == ":ghost-auth-data" #only need the one requested by ghost
        auth_data = output.scan(/"([^"]*)"/).join.split
        if auth_data[6].include? reqid
          image_server_reqid = output.split[6].strip
          $logger.info "found the request id [#{output.split[6]}]"
        end
      end
  end

  if not image_server_reqid.empty?
    cmd2= "#{NSH} #{server_ip} cat #{IMAGELOG} | grep #{image_server_reqid}"
    $logger.info "getting image log set from image server with request id [#{image_server_reqid}]"
    output2 = runCommand(cmd2)
    if not output2.empty?
      image_logs = output2
    end
  end

  return image_logs
end

def findForwardMachineFromImageLog(raw_logs)
  forward_list = Array.new

  raw_logs.each_line do |line|
    log = line.split
    if log[8] == ":fetch" #there could be multiple :fetch ex) watermark
      fetch_info = line.scan(/"([^"]*)"/).join(",").split(",")
      fetch_info.each do |each|
        if each.split.last =~ Resolv::IPv4::Regex ? true : false
          first_edge_ipaddr = each.split.last
          first_request_id = fetch_info[6].split(".").reverse.first
          forward_list.push(putRequestId(first_edge_ipaddr, first_request_id))

          #we would only need the first Edge IP address and request ID.
          break
        end
      end
    end
  end

  return forward_list
end

def ghostGrep(start_time, end_time, reqid, ipaddr, network)
  cmd = "#{GG} --#{network} --use-normandy --range=#{start_time}-#{end_time} '#{reqid}' #{ipaddr}"

  logs = Array.new

  RETRY_GHOSTGREP.times do |index|
    $logger.info "#{index} attempt, running ghost_grep on #{ipaddr}. request id #{reqid}"

    #use %x to see status of ghost_grep
    #output = %x[#{cmd}]
    output = runCommand(cmd)

    output.each_line do |line|
      log_line = line.split
      case log_line.length
        when NUMBER_OF_FIELDS_R, NUMBER_OF_FIELDS_F, NUMBER_OF_FIELDS_S
          if log_line[1] == "f" and log_line[28].include? reqid
            logs.push(line.strip)
          elsif log_line[1] == "r" and log_line[31].include? reqid
            logs.push(line.strip)
          elsif log_line[1] == "S" and log_line[37].include? reqid
            logs.push(line.strip)
          end
      end
    end

    if logs.length > 0
      $logger.info "okay, we have logs"
      break
    elsif logs.length == 0
      $logger.info "oops, could not find any logs"
      countDown(RETRY_DELAY, "will retry in")
    end

    if index == RETRY_GHOSTGREP - 1
      $logger.warn "failed to logs from #{ipaddr}. might try manaully with request id: #{reqid}"
    end
  end

  return logs
end

def findForwardMachine(arr_logs)

  forward_list = Array.new

  arr_logs.each do |log_line|
    if log_line.split[1] == "f"

      object_status = log_line.split[18]
      forward_hostname = log_line.split[23]
      forward_err = log_line.split[29]
      log_source_ip = log_line.split[0]
      request_id = log_line.split[28].split(".").first #request id should always be the first one

      # if the log was the part of sureroute then skip
      # t - the request was an sureroute test object
      # l - if part of an sureroute test client and it lost the race
      # w - if part of an Sureroute test client and it won the race
      if object_status =~ /[l|w|t]/
        next
      end

      #if it was to parent
      if object_status =~ /p/
        #if the request was forwared to a machine within the same region
        #that is not the log we're looking for
        if not forward_err == "ERR_DNS_IN_REGION"
          forward_ipaddr = log_line.split[10]
          forward_list.push(putRequestId("parent #{forward_ipaddr}", request_id))

          next #there might be more than one parent
        end
      end

      #if it was to ICP
      if object_status =~ /g/
        if not forward_err == "ERR_DNS_IN_REGION"
          #make sure it has forward hostname as ip address
          begin
            forward_icp = IPAddr.new(forward_hostname)
          rescue IPAddr::InvalidAddressError => error
            $logger.warn "request was forwarded to icp but forward hostname was not an IP address"
            next
          end

          first_octet = log_source_ip.split(".")[0]
          arr_forward_ipaddr = forward_hostname.split(".")
          arr_forward_ipaddr[0] = first_octet
          forward_list.push(putRequestId("icp " + arr_forward_ipaddr.join("."), request_id))
          $logger.info "forwarded to ICP #{forward_icp}. forward IP was changed to #{arr_forward_ipaddr.join(".")}"

          next
        end
      end

      #if it was forwarded to image server
      if object_status =~ /o/ and forward_hostname.include?("mobile.akadns.net")
        return forward_list.push("image_server #{putRequestId(log_line.split[10], request_id)}")
      end
    end
  end

  return forward_list
end

def getRequestId(ipaddr)
  return $ip_and_reqid[ipaddr]
end

def putRequestId(ipaddr, reqid)
  index = 1

  while true
    if not $ip_and_reqid.include? ipaddr
      $ip_and_reqid[ipaddr] = reqid
      $logger.info "new request: #{ipaddr} - #{reqid}"
      break
    elsif $ip_and_reqid.include? ipaddr
      ipaddr = ipaddr.split.last.split("_").first + "_" + index.to_s
      index = index + 1
    end
  end

  return ipaddr
end

def espro(forward)
  ipaddr = forward.split.last.split("_").first
  output = %x[#{ESPRO} #{ipaddr}].strip
  if $?.exitstatus == 1
    return "[es_pro error]"
  elsif $?.exitstatus == 0
    output.each_line do |line|
      if not line.start_with? "#"
        edgescape_data = line.split
        return "[#{edgescape_data[1]} #{edgescape_data[4]} #{edgescape_data[11]} #{edgescape_data[12]}]"
      end
    end
  end
end

############################

if __FILE__ == $0

  options = {}

  optparse = OptionParser.new do |opts|
    opts.banner = "Usage: kurl.rb [options] URL"

    opts.on('-H', '--host HOST', 'Pass host header to server') do |host|
      options[:host] = host
    end

    opts.on('-q', '--quiet', 'Silence output. Print only headers and logs') do
      options[:quiet] = true
    end

    opts.on('-p', '--progress', 'Show progress(%) and slience output') do
      options[:progress] = true
    end

    opts.on('-h', '--help', 'Display help') do
      puts opts
      exit
    end
  end

  begin
    optparse.parse!
  rescue OptionParser::InvalidOption, OptionParser::MissingArgument
    puts optparse
    exit
  end

  unless ARGV.length == 1
    puts optparse
    exit
  end

  url = ARGV[0].strip
  uri = valid_url?(url)

  if not uri.host =~ Resolv::IPv4::Regex ? true : false
    akamai_domain?(uri.host)
  end

  if options[:quiet] or options[:progress]
    output_redir = nil
  else
    output_redir = $stdout
  end
  $logger = Logger.new(output_redir)
  $logger.formatter = proc do |severity, datetime, progname, msg|
    puts "\e[0;36m#{severity.downcase}\e[0m #{msg}"
  end

  case $server_network
    when 'ff'
      req = Net::HTTP::Get.new(uri.to_s)
      req['Pragma'] = PRAGMA
      if options[:host] then req['Host'] = options[:host] end
      http = Net::HTTP.new(uri.host, uri.port)
      res = http.request(req)

      print_header(req, "Request Header")
      print_header(res, "Response Header")

      if not res['X-Akamai-Request-ID'] or not res['X-Cache']
        $logger.warn "request ID or Edge IP does not exist"
        exit
      end

      request_id = res['X-Akamai-Request-ID'].split(".").reverse.first
      edge_ipaddr = %x[dig #{res['X-Cache'].split[2]} +short].strip

    when 'essl'
      curl = "#{CURL} -v -k -o /dev/null '#{uri.to_s}' -H 'Pragma: #{PRAGMA}'"
      if options[:host] then curl = curl + " -H 'Host: #{options[:host]}'" end

      req = Array.new
      res = Array.new

      output = runCommand(curl)
      if not output.empty?
        output.each_line do |line|
          if line.start_with? ">"
            req.push(line[1..line.length].strip)
          elsif line.start_with? "<"
            res.push(line[1..line.length].strip)
          end
        end
      else
        $logger.warn "no response from curl command"
        exit
      end

      print_header(req, "Request Header")
      print_header(res, "Response Header")

      request_id = String.new
      edge_ipaddr = String.new

      res.each do |res_header|
        if res_header.split(":").first == "X-Akamai-Request-ID"
          request_id = res_header.split(":").last.strip.split(".").reverse.first
        elsif res_header.split(":").first == "X-Cache"
          edge_hostname = res_header.split(":").last.strip.split[2]
          edge_ipaddr = %x[dig #{edge_hostname} +short].strip
        end
      end

      if request_id.empty? or edge_ipaddr.empty?
        $logger.warn "request ID or Edge IP does not exist"
        exit
      end
  end

  #Make a delay for logs to be ready
  countDown(START_DELAY, "starts in")

  #grep window
  before_current_time = (Time.now.utc - TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")
  after_current_time = (Time.now.utc + TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")

  #entire logs
  entire_logs = Hash.new

  #forward machine and reqID pair
  putRequestId(edge_ipaddr, request_id)

  #forward list in order
  forward_list = [edge_ipaddr]

  #interate list index
  forward_index = 0

  while true

    overall_progress = 0

    if options[:progress]
      current_progress = (forward_index.to_f / forward_list.length.to_f * 100).to_i
      overall_progress = current_progress if overall_progress < current_progress
      print "\rProgress: #{overall_progress}%"
      $stdout.flush
    end

    if forward_index == forward_list.length
      $logger.info "completed."
      break
    end

    forward_next = forward_list[forward_index]
    forward_server_ip = forward_next.split.last.split("_").first

    if forward_next.include? "image_server"
      $logger.info "found #{forward_next}"
      image_logs = grepLogFromImageServer(getRequestId(forward_next.split[1]), forward_server_ip)
      entire_logs[forward_next] = image_logs
      forward_ips = findForwardMachineFromImageLog(image_logs)
    elsif forward_server_ip =~ Resolv::IPv4::Regex ? true : false
      logs = ghostGrep(before_current_time, after_current_time, getRequestId(forward_next), forward_server_ip, $server_network)
      entire_logs[forward_next] = logs
      forward_ips = findForwardMachine(logs)
    end

    if forward_ips.length > 0
      $logger.info "request was forwarded to #{forward_ips.inspect}"
      forward_list.concat(forward_ips)
      $logger.info "forward list updated #{forward_list.inspect}. current index #{forward_index}"
    end

    forward_index = forward_index.next
  end #while end

  puts "\n"
  forward_list.each do |forward|
    puts "[#{forward}] #{espro(forward)}\n"
    if entire_logs[forward].empty?
      puts "no log was found."
    else
      puts entire_logs[forward]
    end
    puts "\n"
  end

end #end
