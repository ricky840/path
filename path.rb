#!/usr/bin/env ruby

require 'net/http'
require 'uri'
require 'resolv'

#Location of ghost_grep command in LSG
GG = "/usr/local/akamai/tools/bin/ghost_grep"

#Set how many times it will try ghost_grep to fetch logs
RETRY_GHOSTGREP = 10

#Set number of log fields
NUMBER_OF_FIELDS_F = 58
NUMBER_OF_FIELDS_R = 75

#Time window(sec) for fetching logs
TIME_WINDOW = 300

#Network (ff/essl) default freeflow
server_network = "ff"

unless ARGV.length == 1
  puts "\n"
  puts "Usage:"
  puts "   kurl.rb URL"
  puts "   kurl.rb http://www.foo.com/apple.jpg"
  puts "\n"
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
    puts
    puts "##################################"
    puts "# Request Header"
    puts "##################################"
    puts "#{obj.method} #{obj.path}"
    obj.each_capitalized do |header, value|
      puts "#{header}: #{value}"
    end
  else
    puts
    puts "##################################"
    puts "# Response Header"
    puts "##################################"
    puts "#{obj.code} #{obj.message}"
    obj.each_capitalized do |header, value|
      puts "#{header}: #{value}"
    end
  end
end

def countdown(seconds, msg)
  seconds.downto(1) do |index|
    puts "#{msg} #{index}"
    sleep 1
  end
end

def ghost_grep(start_time, end_time, string, ipaddr, network)
  cmd = "#{GG} --#{network} --use-normandy --range=#{start_time}-#{end_time} #{string} #{ipaddr}"
  puts
  puts "##################################"
  puts "Running #{cmd}"
  puts "##################################"
  puts

  logs = Array.new

  RETRY_GHOSTGREP.times do |index|
    puts
    puts "##################################"
    puts "#{index} attempt"
    puts "##################################"
    puts

    output = %x[#{cmd}]
    output.each_line do |line|
      if line.split.length == NUMBER_OF_FIELDS_R or line.split.length == NUMBER_OF_FIELDS_F
        logs.push(line)
      end
    end

    if logs.length > 0
      puts
      puts "##################################"
      puts "Yay we got the logs!"
      puts "##################################"
      puts
      break
    elsif logs.length == 0
      puts
      puts "##################################"
      puts "Grrrrrr no log was found"
      puts "##################################"
      puts
      countdown(10, "Retry to fetch logs in")
    end

    if index == RETRY_GHOSTGREP
      puts
      puts "##################################"
      puts "Could not find any logs for #{url}"
      puts "Bye!"
      puts
      exit
    end
  end

  return logs
end

def find_forward_machine(arr_logs)
  arr_logs.each do |log_line|
    if log_line.split[1] == "f"

      object_status = log_line.split[18]

      #if the log was the part of sureroute then skip
      # t - the request was an sureroute test object
      # l - if part of an sureroute test client and it lost the race
      # w - if part of an Sureroute test client and it won the race
      if object_status =~ /[l|w|t]/
        next
      end

      #if it was to ICP or Parent
      if object_status =~ /[g|p]/
        #if the request was forwared to a machine within the same region
        #that is not the case we're looking for
        if not log_line.split[29] == "ERR_DNS_IN_REGION"
          forward_ipaddr = log_line.split[10]
          return forward_ipaddr
        end
      end

      #if it was forwared to image server
      if object_status =~ /o/ and log_line.split[23].include?("mobile.akadns.net")
        return "image_server"
      end
    end
  end
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

#Make a request
req = Net::HTTP::Get.new(uri.to_s)
req['Pragma'] = "akamai-x-cache-on, akamai-x-get-request-id, akamai-x-cache-remote-on"
http = Net::HTTP.new(uri.host, uri.port)
res = http.request(req)

#Print headers
prt_header(req)
prt_header(res)

#Get necessary info to fetch the log
ReqId = res['X-Akamai-Request-ID'].split(".").reverse
EdgeIPAddr = %x[dig #{res['X-Cache'].split[2]} +short]
if res['X-Cache'].split[0].include? "MISS"
  if res.key? "X-Cache-Remote"
    ParentIPAddrFrmHeader = %x[dig #{res['X-Cache-Remote'].split[2]} +short]
  end
end

#Print info
puts
puts "##################################"
puts "# Edge IP - #{EdgeIPAddr}"
puts "# Parent IP - #{defined?(ParentIPAddrFrmHeader) ? ParentIPAddrFrmHeader : 'nope, no parent this time'}"
puts "# Request IDs - #{ReqId.inspect}"
puts "##################################"
puts

#Give logs sometime to be fetched
countdown(5, "Fetching logs in")

#Get time windown +-5 mins of current time
before_current_time = (Time.now.utc - TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")
after_current_time = (Time.now.utc + TIME_WINDOW).strftime("%m/%d/%Y/%H:%M")

#Fetch log
all_logs = Array.new
forward_server_list = [EdgeIPAddr]
ReqId.each_with_index do |request_id, index|

  logs = ghost_grep(before_current_time, after_current_time, request_id, forward_server_list[index], server_network)
  all_logs.push(logs)

  #See if there was a forward machine
  forward_machine_ip = find_forward_machine(logs)
  if forward_machine_ip =~ Resolv::IPv4::Regex ? true : false
    puts
    puts "##################################"
    puts "Okay there was a forward machine. Fetching next one"
    puts "##################################"
    puts

    forward_server_list.push(forward_machine_ip)
    next
  elsif forward_machine_ip == "image_server"
    puts
    puts "##################################"
    puts "Image server was found. Not ready yet ;)"
    puts "##################################"
    puts
    break
  else
    puts
    puts "DONE!"
    puts
    break
  end
end

#Show logs
puts
puts "#################################"
puts "LOGS"
puts "#################################"
puts
all_logs.each_with_index do |each_log, index|
  puts "[From #{forward_server_list[index].strip}]"
  each_log.each do |each_log_line|
    puts each_log_line
  end
  puts
end
