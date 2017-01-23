#!/usr/bin/env ruby

require 'net/http'
require 'uri'
require 'resolv'
require 'ipaddr'
require 'open3'
require 'logger'
require 'optparse'
require 'timeout'

ESPRO = "/usr/local/akamai/tools/bin/es_pro"
CURL = "/usr/bin/curl"
NSH = "/usr/local/akamai/bin/nsh"
IMAGELOG = "/a/logs/web_tomcat/catalina.out"
PRAGMA = "akamai-x-cache-on, akamai-x-get-request-id, akamai-x-cache-remote-on"

$retry_ghostgrep = 10
RETRY_DELAY = 0 #0 is 1 seconds
START_DELAY = 2 #seconds
$cmdtimeout = 30 #seconds

def akamai_domain?(domain)
  lookup = %x[dig #{domain} +short].split("\n")
  lookup.each do |each|
    if each =~ /.*akamaiedge\.net\./ or each =~ /.*akamai\.net\./
      return
    end
  end
  puts "Entered hostname is not on Akamai"
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
    # printMsg "#{msg} #{sec}"
    printMsg "#{msg}"
    sleep 1
  end
  printMsg "#{msg} now, working.."
end

def printMsg(msg)
  print "\e[0;36m#{msg.ljust(80)}\e[0m\r"
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
      request_ids = fetch_info.last.split(".").reverse
      request_id_to_grep = request_ids.first
      fetch_info.each do |each|
        if each.split.last =~ Resolv::IPv4::Regex ? true : false
          edge_ipaddr = each.split.last
          forward_list.push({
            :reqid => request_id_to_grep,
            :forward_ipaddr => edge_ipaddr,
            :reqid_to_grep => request_id_to_grep,
            :server_type => "edge"
          })
          break
        end
      end
    end
  end

  return forward_list
end

def ghostGrep(reqid, ipaddr, options={})
  logfile = "/a/logs/ghost.ddc.log.gz"
  if options[:staging] then logfile = "/a/logs/ghost.ddc.log" end
  shellcmd = "nsh #{ipaddr} grep #{reqid} #{logfile}"
  logs = Array.new

  $retry_ghostgrep.times do |index|
    $logger.info "(#{index}/#{$retry_ghostgrep}) grep log from #{ipaddr}. request id #{reqid}"
    printMsg("crawling #{ipaddr} #{reqid} (#{index}/#{$retry_ghostgrep})")

    output = runCommand(shellcmd)
    if output
      output.each_line do |line|
        log_line = line.split

        #insert server ip to the first field to have the same format as ghost_grep log
        log_line.insert(0, ipaddr)

        if log_line[1] == "f" and log_line[28].split(".").include? reqid
          logs.push log_line.join(" ")
        elsif log_line[1] == "r" and log_line[31].split(".").include? reqid
          logs.push log_line.join(" ")
        elsif log_line[1] == "S" and log_line[37].split(".").include? reqid
          logs.push log_line.join(" ")
        end
      end
    end

    if logs.length > 0
      $logger.info "#{ipaddr} found logs".ljust(80)
      printMsg("#{ipaddr} found logs".ljust(80))
      break
    elsif logs.length == 0
      $logger.info "#{ipaddr} oops, could not find any logs".ljust(80)
      countDown(RETRY_DELAY, "retrying #{ipaddr} #{reqid} (#{index}/#{$retry_ghostgrep})")
    end

    if index == $retry_ghostgrep - 1
      $logger.warn "#{ipaddr} #{reqid} failed. try again?"
      printMsg "#{ipaddr} #{reqid} failed. try again?"
    end
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

      log_fields = log_line.split
      object_status = log_fields[18]
      forward_hostname = log_fields[23]
      forward_err = log_fields[29]
      log_source_ip = log_fields[0]
      client_ipaddr = log_fields[11]
      forward_ipaddr = log_fields[10]
      request_id = log_fields[28].split(".").first #request id should always be the first one
      request_id_to_grep =  log_fields[28].split(".").reverse.first

      # if the log was the part of sureroute then skip
      # t - the request was an sureroute test object
      # l - if part of an sureroute test client and it lost the race
      # w - if part of an Sureroute test client and it won the race
      if object_status =~ /[l|w|t]/
        next
      end

      #if it was to parent
      if object_status =~ /p/
        #if the request was forwared to a machine within the same region, that is not the log we're looking for
        if not forward_err == "ERR_DNS_IN_REGION"
          forward_list.push({
            :reqid => request_id,
            :reqid_to_grep => request_id_to_grep,
            :client_ipaddr => client_ipaddr,
            :forward_ipaddr => forward_ipaddr,
            :forward_hostname => forward_hostname,
            :ghost_ip => log_source_ip,
            :server_type => "parent"
          })
          next #there might be more than one parent
        end
      end

      #if it was to icp
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
          forward_list.push({
            :reqid => request_id,
            :reqid_to_grep => request_id_to_grep,
            :client_ipaddr => client_ipaddr,
            :forward_ipaddr => arr_forward_ipaddr.join("."),
            :forward_hostname => forward_hostname,
            :ghost_ip => log_source_ip,
            :server_type => "icp"
          })
          $logger.info "forwarded to icp #{forward_icp}. forward IP was changed to #{arr_forward_ipaddr.join(".")}"

          next
        end
      end

      #if it was forwarded to image server
      if object_status =~ /o/ and forward_hostname.include?("mobile.akadns.net")
        forward_list.push({
          :reqid => request_id,
          :reqid_to_grep => request_id, #image server logs last(latest) request id, not the first one.
          :client_ipaddr => client_ipaddr,
          :forward_ipaddr => forward_ipaddr,
          :forward_hostname => forward_hostname,
          :ghost_ip => log_source_ip,
          :server_type => "image_server"
        })
        return forward_list
      end
    end
  end

  return forward_list
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

  #start ghost
  request_id = options[:request_id]
  edge_ipaddr = options[:ghost_ip]

  output_redir = $stdout if options[:verbose]
  $logger = Logger.new(output_redir)
  $logger.formatter = proc do |severity, datetime, progname, msg|
    puts "\e[0;36m#{severity}:\e[0m #{msg}".ljust(80)
  end

  #if there was url input
  if not url.nil?
    uri = valid_url?(url)
    if not uri.host =~ Resolv::IPv4::Regex ? true : false
      akamai_domain?(uri.host)
    end

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
      elsif res_header.split(":").first == "X-Akamai-Staging"
        options[:staging] = true
      end
    end

    if request_id.empty? or edge_ipaddr.empty?
      $logger.warn "request ID or Edge IP does not exist"
      exit
    end
  end

  #Make a delay for logs to be ready
  #countDown(START_DELAY, "Starts in")

  processed_work_list = {}

  forward_list = Array.new
  forward_index = 0
  forward_list.push({
    :ghost_ip => edge_ipaddr,
    :reqid => "",
    :reqid_to_grep => request_id,
    :client_ipaddr => "",
    :forward_ipaddr => "",
    :forward_hostname => "",
    :server_type => "edge"
  })

  #gogogo
  while true

    if forward_index == forward_list.length
      $logger.info "no more servers left to fetch"
      break
    end

    number_of_incomplete_forwards = forward_list[forward_index..forward_list.length-1].length
    $logger.info "#{number_of_incomplete_forwards} server(s) in queue"
    printMsg("#{number_of_incomplete_forwards} server(s) in queue")

    lock = Mutex.new
    workers = Array.new

    forward_machines_with_duplicates = Array.new
    (forward_index..forward_list.length-1).each do |index|
      worker = Thread.new {
        server = forward_list[index]

        #register
        lock.synchronize {
          if processed_work_list[server[:ghost_ip]].nil?
            processed_work_list[server[:ghost_ip]] = [server[:reqid_to_grep]]
          else
            processed_work_list[server[:ghost_ip]].push(server[:reqid_to_grep])
          end
        }

        if server[:server_type].include? "image_server"
          image_logs = grepLogFromImageServer(server[:reqid_to_grep], server[:ghost_ip])
          lock.synchronize {
            forward_list[index][:log] = image_logs
            forward_machines_with_duplicates.concat(findForwardMachineFromImageLog(image_logs))
          }
        elsif server[:ghost_ip] =~ Resolv::IPv4::Regex ? true : false
          logs = ghostGrep(server[:reqid_to_grep], server[:ghost_ip], {:staging => options[:staging]})
          lock.synchronize {
            forward_list[index][:log] = logs
            forward_machines_with_duplicates.concat(findForwardMachine(logs))
          }
        end
      }
      worker[:name] = "#{forward_list[index][:ghost_ip]}"
      workers.push(worker)
    end

    workers.each do |t|
      t.join
      $logger.info "#{t[:name]} finished"
      printMsg("#{t[:name]} finished")
    end

    #filter out forward_machine has already been processed
    #$logger.info "Processed list for now: #{processed_work_list.inspect}"
    forward_machines_with_duplicates.each_with_index do |f_line, index|
      if processed_work_list.key? f_line[:forward_ipaddr] and processed_work_list[f_line[:forward_ipaddr]].include? f_line[:reqid_to_grep]
        $logger.info "Already processed: #{f_line[:forward_ipaddr]} #{f_line[:reqid_to_grep]}"
      else #never processed server
        forward_list.push({
          :ghost_ip => f_line[:forward_ipaddr],
          :reqid_to_grep => f_line[:reqid_to_grep],
          :server_type => f_line[:server_type]
        })
        $logger.info "New forward machine #{f_line[:forward_ipaddr]} - #{f_line[:reqid]} found"
      end
    end

    #increase pointer
    forward_index = forward_index + number_of_incomplete_forwards
  end #while end

  printMsg "Complete"
  puts
  puts

  forward_list.each do |each_server|
    server_type = "#{each_server[:server_type]}"
    server_ip = "#{each_server[:ghost_ip]}"
    puts server_type != "" ? "[#{server_type} #{server_ip} - #{espro(server_ip)}]" : "[#{server_ip} - #{espro(server_ip)}]"
    if not each_server[:log].empty?
      each_server[:log].each do |log_line|
        puts log_line
      end
    else
      puts "could not find log. try increasing the number of retry and timeout?"
    end
    puts
  end

  if options[:purge]
    forward_list.each_with_index do |forward, index|
      ghostip = forward[:ghost_ip]

      #if url does not exist, use arl from r log
      arl = nil
      if url.nil? and index.eql? 0
        logs = forward[:log]
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
      puts "Purge URL: #{url}" if index.eql? 0

      printMsg "Purging: #{ghostip}"
      result = purgeObj(ghostip, url)
      if result == true
        printMsg "Purging: #{ghostip} - Success\n"
      elsif result == nil
        printMsg "Purging: #{ghostip} - Object does not exist\n"
      else
        printMsg "Purging: #{ghostip} - Failed\n"
      end
    end
  end

end #end
