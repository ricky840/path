#!/usr/bin/env ruby

require 'net/http'
require 'uri'
require 'resolv'
require 'ipaddr'
require 'open3'
require 'logger'

#Command locations in LSG
GG = "/usr/local/akamai/tools/bin/ghost_grep"
ESPRO = "/usr/local/akamai/tools/bin/es_pro"
CURL = "/usr/bin/curl"
NSH = "/usr/local/akamai/bin/nsh"

#Location of image server log
IMAGELOG = "/a/logs/web_tomcat/catalina.out"

#Set how many times it will try ghost_grep
RETRY_GHOSTGREP = 10

#Set how many times it will try grep logs from image server(yet implemented)
RETRY_IMAGE_LOG = 3

#Set number of log fields
NUMBER_OF_FIELDS_F = 58
NUMBER_OF_FIELDS_R = 75
NUMBER_OF_FIELDS_S = 59

#Time window(sec) for grep logs
TIME_WINDOW = 300

#Network (ff/essl) default is freeflow
$server_network = "ff"

#Hash that holds forward_machine/request_id
$ip_and_reqid = Hash.new

#logger
$logger = Logger.new($stdout)
$logger.formatter = proc do |severity, datetime, progname, msg|
  #date_format = datetime.strftime('%Y-%m-%d %H:%M:%S')
  puts "[#{severity}] #{msg}"
end

def akamai_domain?(domain)
  lookup = %x[dig #{domain} +short].split("\n")
  lookup.each do |each|
    if each =~ /.*akamaiedge\.net\./ or each =~ /.*akamai\.net\./
      return
    end
  end
  puts "Hostname is not on Akamai"
  exit
end

def valid_url?(url)
  uri = URI.parse(URI.encode(url))
  if not uri.kind_of?(URI::HTTP)
    puts "URL is not valid"
    exit
  end

  if uri.kind_of?(URI::HTTPS)
    $server_network = "essl"
  end

  if uri.path.empty?
    uri.path = "/"
  end

  return uri
end

def prt_header(obj)
  if obj.class == Net::HTTP::Get
    puts "[Request Header]"
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
    puts "[Response Header]"
    puts "#{obj.code} #{obj.message}"
    obj.each_capitalized do |header, value|
      puts "#{header}: #{value}"
    end
    puts "\n"
  end
end

def countdown(seconds, msg)
  seconds.downto(0) do |index|
    print "\r[INFO] #{msg} #{index}"
    $stdout.flush
    sleep 1
  end
  puts "\n"
end

def grep_log_imageserver(reqid, server_ip)
  cmd = "#{NSH} #{server_ip} cat #{IMAGELOG} | grep #{reqid}"

  image_logs = String.new
  image_server_reqid = String.new

  $logger.info "Pulling log to find image server request id"
  Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
    stdin.close
    if $?.exited?
      output = stdout.read
      case output.split("\n").size
        when 0
          $logger.info "Could not find any logs from image server."
        else
          $logger.info "Found log, validating.."
          if output.split[7] == ":ghost-auth-data" #only need the one requested by ghost
            auth_data = output.scan(/"([^"]*)"/).join.split
            if auth_data[6].include? reqid
              image_server_reqid = output.split[6].strip
              $logger.info "Found the request id [#{output.split[6]}] from the image server."
            end
          end
      end
    else
      $logger.warn "There was an error with running command. Exitstatus: #{$?.exitstatus}"
    end
  end #open3 end

  if not image_server_reqid.empty?
    cmd_greplog = "#{NSH} #{server_ip} cat #{IMAGELOG} | grep #{image_server_reqid}"

    $logger.info "Pulling image server logs with request id [#{image_server_reqid}]"
    Open3.popen3(cmd_greplog) do |stdin, stdout, stderr, wait_thr|
      stdin.close
      if $?.exited?
        output = stdout.read
        if not output.empty?
          image_logs = output
        end
      else
        $logger.warn "There was an error with running command. Exitstatus: #{$?.exitstatus}"
      end
    end #open3 end
  end

  return image_logs
end

def find_forward_machine_from_imagelog(raw_logs)
  forward_list = Array.new

  raw_logs.each_line do |line|
    log = line.split
    if log[8] == ":fetch" #there could be multiple :fetch ex) watermark
      fetch_info = line.scan(/"([^"]*)"/).join(",").split(",")
      fetch_info.each do |each|
        if each.split.last =~ Resolv::IPv4::Regex ? true : false
          first_edge_ipaddr = each.split.last
          first_request_id = fetch_info[6].split(".").reverse.first
          forward_list.push(put_request_id(first_edge_ipaddr, first_request_id))

          #we would only need the first Edge IP address and request ID.
          break
        end
      end
    end
  end

  return forward_list
end

def ghost_grep(start_time, end_time, reqid, ipaddr, network)
  cmd = "#{GG} --#{network} --use-normandy --range=#{start_time}-#{end_time} #{reqid} #{ipaddr}"
  # puts "Running #{cmd}"
  $logger.info "Running ghost_grep on #{ipaddr} with request id #{reqid}"

  logs = Array.new

  RETRY_GHOSTGREP.times do |index|
    $logger.info "#{index} attempt in grepping logs from #{ipaddr}"

    #use %x to see status of ghost_grep
    #output = %x[#{cmd}]
    output = String.new

    Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
      stdin.close
      output = stdout.read
      if $?.exited?
        $logger.info "ghost_grep ran successfully with pid #{$?.pid}"
      else
        $logger.warn "It seems there was an issue with running ghost_grep. Exitstatus: #{$?.exitstatus}"
        next
      end
    end

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
      $logger.info "Pulled log successfully."
      break
    elsif logs.length == 0
      $logger.info "No log was found"
      countdown(9, "Retry in")
    end

    if index == RETRY_GHOSTGREP - 1
      $logger.warn "Could not find any logs from #{ipaddr}. You might want to try manaully with request id #{reqid}"
    end
  end

  return logs
end

def find_forward_machine(arr_logs)

  #list of forward IP addresses
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
          forward_list.push(put_request_id("parent #{forward_ipaddr}", request_id))

          #there might be more than one parent
          next
        end
      end

      #if it was to ICP
      if object_status =~ /g/
        if not forward_err == "ERR_DNS_IN_REGION"
          #make sure it has forward hostname as ip address
          begin
            forward_icp = IPAddr.new(forward_hostname)
          rescue IPAddr::InvalidAddressError => error
            $logger.warn "Request was forwarded to icp but forward hostname was not an IP address"
            next
          end

          first_octet = log_source_ip.split(".")[0]
          arr_forward_ipaddr = forward_hostname.split(".")
          arr_forward_ipaddr[0] = first_octet
          forward_list.push(put_request_id("icp " + arr_forward_ipaddr.join("."), request_id))
          $logger.info "The request was forwarded to ICP #{forward_icp} and real IP of the server is #{arr_forward_ipaddr.join(".")}"

          next
        end
      end

      #if it was forwarded to image server
      if object_status =~ /o/ and forward_hostname.include?("mobile.akadns.net")
        return forward_list.push("image_server #{put_request_id(log_line.split[10], request_id)}")
      end
    end
  end

  return forward_list
end

def get_request_id(ipaddr)
  return $ip_and_reqid[ipaddr]
end

def put_request_id(ipaddr, reqid)
  index = 1

  while true
    if not $ip_and_reqid.include? ipaddr
      $ip_and_reqid[ipaddr] = reqid
      $logger.info "New request was found: #{ipaddr} - #{reqid} inserted."
      break
    elsif $ip_and_reqid.include? ipaddr
      ipaddr = ipaddr.split.last.split("_").first + "_" + index.to_s
      index = index + 1
    end
  end

  return ipaddr
end

def es_pro(forward)
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

  unless ARGV.length == 1
    puts
    puts "Usage:"
    puts "   kurl.rb URL"
    puts "   kurl.rb http://www.foo.com/apple.jpg"
    puts
    exit
  end

  #Validate URL
  url = ARGV[0].strip
  uri = valid_url?(url)

  #Make sure the domain is on Akamai
  akamai_domain?(uri.host)

  case $server_network
    when 'ff'
      req = Net::HTTP::Get.new(uri.to_s)
      req['Pragma'] = "akamai-x-cache-on, akamai-x-get-request-id, akamai-x-cache-remote-on"
      http = Net::HTTP.new(uri.host, uri.port)
      res = http.request(req)
      request_id = res['X-Akamai-Request-ID'].split(".").reverse.first
      edge_ipaddr = %x[dig #{res['X-Cache'].split[2]} +short].strip
      prt_header(req)
      prt_header(res)
    when 'essl'
      req_header = ["[Request Header]"]
      res_header = ["[Response Header]"]
      curl = "#{CURL} -v -k -o /dev/null #{uri.to_s} -H 'Pragma: akamai-x-cache-on, akamai-x-get-request-id'"
      Open3.popen3(curl) do |stdin, stdout, stderr, wait_thr|
        stdin.close
        if $?.exited?
          output = stderr.read #headers are considered to be debug informations
          if not output.empty?
            output.each_line do |line|
              if line.start_with? ">"
                req_header.push(line[1..line.length].strip)
              elsif line.start_with? "<"
                res_header.push(line[1..line.length].strip)
              end
            end
          end
        else
          $logger.warn "There was an error with running command(curl). Exitstatus: #{$?.exitstatus}"
          exit
        end
      end
      request_id = res_header.detect {|header| header.include? "X-Akamai-Request-ID"}.split(":").last.split(".").reverse.first.strip
      edge_hostname = res_header.detect {|header| header.include? "X-Cache"}.split(":").last.split[2].strip
      edge_ipaddr = %x[dig #{edge_hostname} +short].strip
      prt_header(req_header)
      prt_header(res_header)
  end

  #Make a delay for logs to be ready
  countdown(3, "Starts in")

  #Set time windown +-5 mins of current time
  before_current_time = (Time.now.utc - TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")
  after_current_time = (Time.now.utc + TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")

  #To save all logs
  entire_logs = Hash.new

  #IP and reqID pair
  put_request_id(edge_ipaddr, request_id)

  #forward list in order
  forward_list = [edge_ipaddr]
  forward_index = 0

  while true
    if forward_index == forward_list.length
      $logger.info "Completed."
      break
    end

    forward_next = forward_list[forward_index]
    forward_server_ip = forward_next.split.last.split("_").first

    if forward_next.include? "image_server"
      $logger.info "#{forward_next} was found."
      image_logs = grep_log_imageserver(get_request_id(forward_next.split[1]), forward_server_ip)
      entire_logs[forward_next] = image_logs
      forward_ips = find_forward_machine_from_imagelog(image_logs)
    elsif forward_server_ip =~ Resolv::IPv4::Regex ? true : false
      logs = ghost_grep(before_current_time, after_current_time, get_request_id(forward_next), forward_server_ip, $server_network)
      entire_logs[forward_next] = logs
      forward_ips = find_forward_machine(logs)
    end

    if forward_ips.length > 0
      $logger.info "Request was forwarded to #{forward_ips.inspect}"
      forward_list.concat(forward_ips)
      $logger.info "Forward list updated. #{forward_list.inspect} and current index is #{forward_index}"
    end

    forward_index = forward_index.next
  end #while end

  puts "[LOG]"
  forward_list.each do |forward|
    puts "\n[#{forward}] #{es_pro(forward)}"
    if not entire_logs[forward] == nil
      puts entire_logs[forward]
    else
      puts "No log was found"
    end
  end

end
