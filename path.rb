#!/usr/bin/env ruby

require 'net/http'
require 'uri'
require 'resolv'
require 'ipaddr'
require 'open3'
require 'logger'

#Location of ghost_grep command in LSG
GG = "/usr/local/akamai/tools/bin/ghost_grep"

#Set how many times it will try ghost_grep
RETRY_GHOSTGREP = 10

#Set how many times it will try grep logs from image server
RETRY_IMAGE_LOG = 3

#Set number of log fields
NUMBER_OF_FIELDS_F = 58
NUMBER_OF_FIELDS_R = 75
NUMBER_OF_FIELDS_S = 59

#Time window(sec) for grep logs
TIME_WINDOW = 300

#Network (ff/essl) default is freeflow
server_network = "ff"

unless ARGV.length == 1
  puts
  puts "Usage:"
  puts "   kurl.rb URL"
  puts "   kurl.rb http://www.foo.com/apple.jpg"
  puts
  exit
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
  uri = URI.parse(url)
  if not uri.kind_of?(URI::HTTP)
    puts "URL is not valid"
    exit
  end

  if uri.kind_of?(URI::HTTPS)
    server_network = "essl"
    puts "HTTPS is not ready yet ;)"
    exit
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
    print "\r#{msg} #{index}"
    $stdout.flush
    sleep 1
  end
  puts "\n"
end

def grep_log_imageserver(reqid, server_ip)
  cmd = "nsh #{server_ip} cat /a/logs/web_tomcat/catalina.out | grep #{reqid}"

  image_logs = Array.new
  image_server_reqid = String.new

  $logger.info "Pulling log to find image server request id"
  Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
    stdin.close
    if $?.exited?
      output = stdout.read
      case output.split("\n").size
        when 0
          $logger.info "Could not find any logs from image server."
        when 1
          $logger.info "Found log, validating.."
          if output.split[7] == ":ghost-auth-data"
            auth_data = output.scan(/"([^"]*)"/).join.split
            if auth_data[6].include? reqid
              image_server_reqid = output.split[6].strip
              $logger.info "Found the request id [#{output.split[6]}] from the image server."
            end
          end
        else
          $logger.warn "Found more than 1 log, what should I do?"
      end
    else
      $logger.warn "There was an error with running command. Exitstatus: #{$?.exitstatus}"
    end
  end #open3 end

  if not image_server_reqid.empty?
    cmd_greplog = "nsh #{server_ip} cat /a/logs/web_tomcat/catalina.out | grep #{image_server_reqid}"

    $logger.info "Pulling image server logs with request id [#{image_server_reqid}]"
    Open3.popen3(cmd_greplog) do |stdin, stdout, stderr, wait_thr|
      stdin.close
      if $?.exited?
        output = stdout.read
        if not output.empty?
          if not output.split("\n").size == 9 then $logger.warn "The number of image server logs were not 9. Instead #{output.split("\n").size}" end
          output.each_line do |line|
            image_logs.push(line.strip)
          end
        end
      else
        $logger.warn "There was an error with running command. Exitstatus: #{$?.exitstatus}"
      end
    end #open3 end
  end

  return image_logs
end

def find_forward_machine_from_imagelog(arr_logs)
  forward_list = Array.new

  arr_logs.each do |line|
    log = line.split
    if log[8] == ":fetch" #there could be multiple :fetch(watermark)
      fetch_info = line.scan(/"([^"]*)"/).join(",").split(",")
      $request_id = fetch_info[6].split(".").reverse.first
      $logger.info "Request ID was updated. #{$request_id}"
      fetch_info.each do |each|
        if each.split.last =~ Resolv::IPv4::Regex ? true : false
          forward_list.push(each.split.last)

          #we only need the first IP address.
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
      $logger.info "Pulled log successfully"
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
          forward_list.push(forward_ipaddr)

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
          forward_list.push(arr_forward_ipaddr.join("."))
          $logger.info "The request was forwarded to ICP #{forward_icp} and real IP of the server is #{arr_forward_ipaddr.join(".")}"

          next
        end
      end

      #if it was forwarded to image server
      if object_status =~ /o/ and forward_hostname.include?("mobile.akadns.net")
        $request_id = log_line.split[28].split(".").first
        $logger.info "Request ID was updated. #{$request_id}"
        return forward_list.push("image_server #{log_line.split[10]}")
      end
    end
  end

  return forward_list

end

#############################################
#
# Main
#
#############################################

#Validate URL
url = ARGV[0].strip
uri = valid_url?(url)

#Make sure the domain is on Akamai
akamai_domain?(uri.host)

#Create logger
$logger = Logger.new($stdout)
$logger.formatter = proc do |severity, datetime, progname, msg|
  date_format = datetime.strftime('%Y-%m-%d %H:%M:%S')
  puts "[#{date_format}] #{severity}: #{msg}"
end

#Make a request
req = Net::HTTP::Get.new(uri.to_s)
req['Pragma'] = "akamai-x-cache-on, akamai-x-get-request-id, akamai-x-cache-remote-on"
http = Net::HTTP.new(uri.host, uri.port)
res = http.request(req)

#Print headers
prt_header(req)
prt_header(res)

#Get necessary info to fetch the log
$request_id = res['X-Akamai-Request-ID'].split(".").reverse.first
EdgeIPAddr = %x[dig #{res['X-Cache'].split[2]} +short].strip
if res['X-Cache'].split[0].include? "MISS"
  if res.key? "X-Cache-Remote"
    ParentIPAddrFrmHeader = %x[dig #{res['X-Cache-Remote'].split[2]} +short].strip
  end
end

#Print info
#puts "Edge IP #{EdgeIPAddr}"
#puts "Parent IP #{defined?(ParentIPAddrFrmHeader) ? ParentIPAddrFrmHeader : 'nope, no parent this time'}"
#puts "Request ID #{$request_id}"

#give ghost sometime to logs are ready
countdown(3, "Starts in")

#Get time windown +-5 mins of current time
before_current_time = (Time.now.utc - TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")
after_current_time = (Time.now.utc + TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")

#Pull log
entire_logs = Hash.new
forward_server_list = [EdgeIPAddr]
forward_index = 0
while true
  if forward_index == forward_server_list.length
    $logger.info "Fetched all logs"
    break
  end

  forward_server = forward_server_list[forward_index]

  if forward_server.include? "image_server"
    $logger.info "#{forward_server} was found."
    image_logs = grep_log_imageserver($request_id, forward_server.split[1])
    entire_logs[forward_server] = image_logs
    forward_ips = find_forward_machine_from_imagelog(image_logs)

  elsif forward_server =~ Resolv::IPv4::Regex ? true : false
    logs = ghost_grep(before_current_time, after_current_time, $request_id, forward_server, server_network)
    entire_logs[forward_server] = logs
    forward_ips = find_forward_machine(logs)
  end

  if forward_ips.length > 0
    $logger.info "Request was forwarded to #{forward_ips.inspect}"
    forward_server_list.concat(forward_ips)
    $logger.info "Forward list updated. #{forward_server_list.inspect} and current index is #{forward_index}"
  end

  forward_index = forward_index.next
end #while end

puts "\n[LOG]"
forward_server_list.each do |ipaddress|
  puts "\n[#{ipaddress}]"
  if not entire_logs[ipaddress] == nil
    puts entire_logs[ipaddress]
  else
    puts "No log was found"
  end
end
