#!/usr/bin/env ruby

require 'net/http'
require 'uri'
require 'resolv'
require 'ipaddr'
require 'open3'
require 'logger'
require 'optparse'
require 'timeout'

#GG = "/usr/local/akamai/tools/bin/ghost_grep"
ESPRO = "/usr/local/akamai/tools/bin/es_pro"
CURL = "/usr/bin/curl"
NSH = "/usr/local/akamai/bin/nsh"
IMAGELOG = "/a/logs/web_tomcat/catalina.out"
PRAGMA = "akamai-x-cache-on, akamai-x-get-request-id, akamai-x-cache-remote-on"

$retry_ghostgrep = 5 #changed to nsh
TIME_WINDOW = 300 #seconds
RETRY_DELAY = 5 #seconds
START_DELAY = 2 #seconds
$cmdtimeout = 30 #seconds

#does not use anymore
#NUMBER_OF_FIELDS_F = 59
#NUMBER_OF_FIELDS_R = 76
#NUMBER_OF_FIELDS_S = 59

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
  seconds.downto(0) do |sec|
    printMsg "\e[0;36m#{msg} #{sec} sec\e[0m"
    sleep 1
  end
  printMsg "\e[0;36m#{msg} now, working..\e[0m"
end

def printMsg(msg)
  print "#{msg.ljust(80)}\r"
  $stdout.flush
end

def runCommand(cmd)
  begin
    Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
      Timeout::timeout($cmdtimeout) {
        stdin.close
        if $?.exited?
          result = stdout.read
          if cmd.include? "curl" then result = stderr.read end
          return result
        elsif not $?.exitstatus == 0
          $logger.warn "error occured while running command #{$?.exitstatus}"
          return false
        end
      }
    end
  rescue Timeout::Error => e
    $logger.warn "Timed out".ljust(80)
    return false
  end
end

def grepLogFromImageServer(reqid, server_ip)
  cmd = "#{NSH} #{server_ip} grep #{reqid} #{IMAGELOG}"

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
    cmd2 = "#{NSH} #{server_ip} grep #{image_server_reqid} #{IMAGELOG}"
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
  commands = ["nsh #{ipaddr} grep #{reqid} /a/logs/ghost.ddc.log.gz", "nsh #{ipaddr} grep #{reqid} /a/logs/ghost.ddc.log"]

  logs = Array.new
  locker = Mutex.new

  threads = commands.map do |shellcmd|
    Thread.new {
      thread_name = (shellcmd.include? "gz") ? "T1" : "T2"
      $retry_ghostgrep.times do |index|
        $logger.info "#{thread_name} (#{index}/#{$retry_ghostgrep}) grep log from #{ipaddr}. request id #{reqid}"
        output = runCommand(shellcmd)
        if output
          output.each_line do |line|
            log_line = line.split

            #insert server ip to the first element to have the same format as log from ghost_grep
            log_line.insert(0, ipaddr)

            if log_line[1] == "f" and log_line[28].split(".").include? reqid
              log_line = log_line.join(" ")
              locker.synchronize { logs.push log_line }
            elsif log_line[1] == "r" and log_line[31].split(".").include? reqid
              log_line = log_line.join(" ")
              locker.synchronize { logs.push log_line }
            elsif log_line[1] == "S" and log_line[37].split(".").include? reqid
              log_line = log_line.join(" ")
              locker.synchronize { logs.push log_line }
            end
          end
        end

        if logs.length > 0
          $logger.info "#{thread_name} found logs".ljust(80)
          break
        elsif logs.length == 0
          $logger.info "#{thread_name} oops, could not find any logs".ljust(80)
          countDown(RETRY_DELAY, "(#{index}/#{$retry_ghostgrep}) #{thread_name} retry #{ipaddr} - #{reqid} in")
        end

        if index == $retry_ghostgrep - 1
          $logger.warn "#{thread_name} failed #{ipaddr}. might try manaully with request id: #{reqid} :("
        end
      end
    }
  end

  threads.each do |t|
    t.join
    threads.each { |th| th.kill }
  end

  return logs
end

def purgeObj(ghostip, url)
  cmd = "nsh #{ghostip} purge '#{url}'"
  output = runCommand(cmd).split("\n").first
  return false if output == nil
  if output.include? "200"
    return true
  elsif output.include? "404"
    return nil
  else
    return false
  end
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
        if not forward_err == "ERR_DNS_IN_REGION" #make sure it has forward hostname as ip address
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
        #return "[#{edgescape_data[1]} #{edgescape_data[4]} #{edgescape_data[11]} #{edgescape_data[12]}]"
        return "#{edgescape_data[1]}, #{edgescape_data[4]}"
      end
    end
  end
end

############################

if __FILE__ == $0

  options = {}

  optparse = OptionParser.new do |opts|
    opts.banner = "Usage: crawler.rb [options]"

    opts.on('-u', '--url URL', 'Target URL.') do |input_url|
      options[:url] = input_url
    end

    input_headers = {}
    opts.on('-H', '--header NAME:VALUE', 'Pass header to server. Multiple headers(-H) possible.') do |header|
      header.each do |each_header|
        begin
          raise "#{each_header}" if not each_header.split(":").length == 2
          name, value = each_header.split(":").first.capitalize.strip, each_header.split(":").last.strip
          value += ", #{PRAGMA}" if name.eql? "Pragma"
          input_headers[name] = value
        rescue Exception => e
          puts "Header(#{e.message}) format should be 'Name: value'"
          exit
        end
      end
      options[:header] = input_headers if input_headers.length > 0
    end

    opts.on('-r', '--request_id REQUEST_ID', 'Request Id. You must enter ghost Ip(-g) as well.') do |input_request_id|
      options[:request_id] = input_request_id
    end

    opts.on('-t', '--retry RETRY', 'Number of retry on pulling logs from each ghost. Default is 10.') do |num_retry|
      options[:num_retry] = num_retry.to_i
    end

    opts.on('-T', '--timeout TIMEOUT', 'Timeout in seconds for each try. Default is 15.') do |timeout|
      options[:timeout] = timeout.to_i
    end

    opts.on('-p', '--purge', 'Purge object after fetching logs. This will purge through ghosts.') do
      options[:purge] = true
    end

    opts.on('-v', '--verbose', 'Show more informations. Noisy output.') do
      options[:verbose] = true
    end

    opts.on('-g', '--ghost GHOST_IP', 'Ghost IP address. Request Id(-r) is required.') do |input_ghost_ip|
      options[:ghost_ip] = input_ghost_ip
    end

    opts.on('-h', '--help', 'Display help.') do
      puts opts
      exit
    end
  end

  begin
    optparse.parse!
    if options[:request_id] != nil or options[:ghost_ip] != nil
      if options[:request_id] == nil or options[:ghost_ip] == nil
        raise OptionParser::MissingArgument
      else
        #validate ghost ip format
        if not options[:ghost_ip] =~ Resolv::IPv4::Regex ? true : false
          raise OptionParser::MissingArgument
        end
        #we have req/ghost set
        options[:urldontneed] = true
      end
    end
    if not options[:urldontneed]
      raise OptionParser::MissingArgument if options[:url].nil?
    end
  rescue OptionParser::InvalidOption, OptionParser::MissingArgument
    puts optparse
    exit
  end

  url = options[:url]
  $timeout = options[:timeout] if not options[:timeout].nil?
  $retry_ghostgrep = options[:num_retry] if not options[:num_retry].nil?

  #first machine
  request_id = options[:request_id]
  edge_ipaddr = options[:ghost_ip]

  output_redir = $stdout if options[:verbose]
  $logger = Logger.new(output_redir)
  $logger.formatter = proc do |severity, datetime, progname, msg|
    puts "\e[0;36m#{severity}:\e[0m #{msg}"
  end

  #if there was url input
  if not url.nil?
    uri = valid_url?(url)
    if not uri.host =~ Resolv::IPv4::Regex ? true : false
      akamai_domain?(uri.host)
    end

    case $server_network
      when 'ff'
        req = Net::HTTP::Get.new(uri.to_s)
        req['Pragma'] = PRAGMA

        if not options[:header].nil?
          options[:header].each do |header_name, header_value|
            req[header_name] = header_value
          end
        end

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

        if not options[:header].nil?
          options[:header].each do |header_name, header_value|
            curl = curl + " -H '#{header_name}: #{header_value}'"
          end
        end

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
  end

  #Make a delay for logs to be ready
  countDown(START_DELAY, "Start in")

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

    if forward_index == forward_list.length
      $logger.info "completed."
      break
    end

    forward_next = forward_list[forward_index]
    forward_server_ip = forward_next.split.last.split("_").first

    if forward_next.include? "image_server"
      $logger.info "found #{forward_next}"
      printMsg "\e[0;36mCrawling:\e[0m #{forward_next} - #{getRequestId(forward_next.split[1])}"
      image_logs = grepLogFromImageServer(getRequestId(forward_next.split[1]), forward_server_ip)
      entire_logs[forward_next] = image_logs
      forward_ips = findForwardMachineFromImageLog(image_logs)
    elsif forward_server_ip =~ Resolv::IPv4::Regex ? true : false
      printMsg "\e[0;36mCrawling:\e[0m #{forward_next} - #{getRequestId(forward_next)}"
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

  printMsg "\e[0;36mComplete\e[0m"
  puts "\n" if not options[:verbose]
  puts

  forward_list.each do |forward|
    puts "\e[0;36m[#{forward}] [#{espro(forward)}]\e[0m\n"
    if entire_logs[forward].empty?
      puts "no log was found."
    else
      puts entire_logs[forward]
    end
    puts "\n"
  end

  if options[:purge]
    forward_list.each_with_index do |forward, index|
      ghostip = forward.split.last.split("_").first

      #if url does not exist, use arl from r log
      arl = nil
      if url.nil? and index.eql? 0
        logs = entire_logs[forward]
        logs.each do |log_line|
          log_fields = log_line.split
          case log_fields[1]
          when "r"
            arl = log_fields[12]
            break
          when "S"
            protocol = log_fields[20] == "-" ? "http://" : "https://"
            host = log_fields[32]
            uri = log_fields[30] == "-" ? "/" : "/" + log_fields[30]
            arl = protocol + host + uri
          end
        end
      end

      url = arl if not arl.nil?
      puts "\e[0;36mPurge URL:\e[0m #{url}" if index.eql? 0

      printMsg "\e[0;36mPurging:\e[0m #{ghostip}"
      result = purgeObj(ghostip, url)
      if result == true
        printMsg "\e[0;36mPurging:\e[0m #{ghostip} - Success\n"
      elsif result == nil
        printMsg "\e[0;36mPurging:\e[0m #{ghostip} - Object does not exist\n"
      else
        printMsg "\e[0;36mPurging:\e[0m #{ghostip} - Failed\n"
      end
    end
  end

end #end
