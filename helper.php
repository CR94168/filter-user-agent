<?php
$isMobile = false;
$isCrawler = false;
function filter_client()
{

    global $isMobile;
    global $isCrawler;


    $mobile_agents = '!(tablet|pad|mobile|phone|symbian|android|ipod|ios|blackberry|webos)!i';

    // pattern
    // $patterns = ['google','bot','Googlebot','CheckMarkNetwork','bingbot','AdsBot','Screaming','Frog','Slurp','DuckDuckBot','Baiduspider','SiteSucker'];

    $file_pattern = file_get_contents("./pattern.json");
    $patterns = json_decode($file_pattern);

    //var_dump($patterns);

    echo "<pre>\n";
    echo "checking...<br/>";
    echo "</pre>\n";


    // get_var
    $get_referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : 'no_referer';
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'default_ua';
    $http_from = isset($_SERVER['HTTP_FROM']) ? $_SERVER['HTTP_FROM'] : 'default_from';
    $request_time = isset($_SERVER['REQUEST_TIME']) ? $_SERVER['REQUEST_TIME'] : microtime(true);
    $http_do_connecting_ip = isset($_SERVER['HTTP_DO_CONNECTING_IP']) ? $_SERVER['HTTP_DO_CONNECTING_IP'] : null;
    $http_cf_connecting_ip = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : null;
    $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;
    //$ip = isset($http_do_connecting_ip) ? $http_do_connecting_ip : $remote_addr;

    if (isset($http_cf_connecting_ip)) {
        $ip = $http_cf_connecting_ip;
    } else if (isset($http_do_connecting_ip)) {
        $ip = $http_do_connecting_ip;
    } else if (isset($remote_addr)) {
        $ip = $remote_addr;
    } else {
        $ip = "default_ip";
    }

    $browser_name = get_browser_name($user_agent);

    if (preg_match($mobile_agents, $user_agent)) {
        $isMobile = true;
    }

    if (check_pattern($patterns, $browser_name)) {
        // echo "detect-suspicious-browser-name"."<br/>";
        $isCrawler = true;
        log_detect($request_time, $ip, $browser_name, "detect-suspicious-browser-name");
    } else if (check_pattern($patterns, $user_agent)) {
        // echo "detect-suspicious-user-agnet"."<br/>";
        $isCrawler = true;
        log_detect($request_time, $ip, $user_agent, "detect-suspicious-user-agent");
    } else if (check_pattern($patterns, $http_from)) {
        // echo "detect-suspicious-http-from"."<br/>";
        $isCrawler = true;
        log_detect($request_time, $ip, $http_from, "detect-suspicious-http-from");
    } else {
        // allow access page
        echo "<pre>\n";
        echo "allow-access-page" . "<br/>";
        echo "request_time : " . $request_time . "<br/>";
        echo "browser_name : " . $browser_name . "<br/>";
        echo "user_agent : " . $user_agent . "<br/>";
        echo "http_from : " . $http_from . "<br/>";
        echo "get_referer : " . $get_referer . "<br/>";
        echo "http_cf_connecting_ip : " . $http_cf_connecting_ip . "<br/>";
        echo "http_do_connecting_ip : " . $http_do_connecting_ip . "<br/>";
        echo "remote_addr : " . $remote_addr . "<br/>";
        echo "ip : " . $ip . "<br/>";
        echo "isMobile : " . $isMobile . "<br/>";
        echo "</pre>\n";
        $write = date("Y.m.d.H.i.s.") . $request_time . " : [" . $ip . "] -> " . $browser_name . " -> " . $user_agent . "\n";
        file_put_contents('./ACCESS_' . date("Y.m.d") . '.log', $write, FILE_APPEND);
    }

    echo "<pre>\n";
    echo "finish" . "<br/>";
    echo "</pre>\n";

    $result = array(
        "isMobile" => $isMobile,
        "isCrawler" => $isCrawler,
        "browser_name" => $browser_name,
        "user_agent" => $user_agent,
        "http_from" => $http_from,
        "get_referer" => $get_referer,
        "http_cf_connecting_ip" => $http_cf_connecting_ip,
        "http_do_connecting_ip" => $http_do_connecting_ip,
        "remote_addr" => $remote_addr,
        "ip" => $ip,
        "request_time" => $request_time
    );

    return $result;
}

function log_detect($request_time, $ip, $object, $desc)
{
    global $isCrawler;
    echo "<pre>\n";
    echo "detect-suspicious-activity" . "<br/>";
    echo "isCrawler : " . $isCrawler . "<br/>";
    echo "request_time : " . $request_time . "<br/>";
    echo "ip : " . $ip . "<br/>";
    echo "object : " . $object . "<br/>";
    echo "desc : " . $desc . "<br/>";
    echo "</pre>\n";
    $write = date("Y.m.d.H.i.s.") . $request_time . " : [" . $ip . "] -> " . $object . " -> " . $desc . "\n";
    file_put_contents('./DETECT_' . date("Y.m.d") . '.log', $write, FILE_APPEND);
}

function check_pattern($patterns, $object)
{
    $lowercaseObject = strtolower($object);

    foreach ($patterns as $pattern) {
        $lowercasePattern = strtolower($pattern);

        if (stripos($lowercaseObject, $lowercasePattern) !== false) {
            return true;
        }
    }

    return false;
}

function get_browser_name($user_agent)
{
    $t = strtolower($user_agent);
    $t = " " . $t;

    // Humans / Regular Users     
    if (strpos($t, 'opera') || strpos($t, 'opr/')) return 'Opera';
    elseif (strpos($t, 'edge')) return 'Edge';
    elseif (strpos($t, 'chrome')) return 'Chrome';
    elseif (strpos($t, 'safari')) return 'Safari';
    elseif (strpos($t, 'firefox')) return 'Firefox';
    elseif (strpos($t, 'msie') || strpos($t, 'trident/7')) return 'Internet Explorer';

    // Search Engines 
    elseif (strpos($t, 'google')) return '[Bot] Googlebot';
    elseif (strpos($t, 'bing')) return '[Bot] Bingbot';
    elseif (strpos($t, 'slurp')) return '[Bot] Yahoo! Slurp';
    elseif (strpos($t, 'duckduckgo')) return '[Bot] DuckDuckBot';
    elseif (strpos($t, 'baidu')) return '[Bot] Baidu';
    elseif (strpos($t, 'yandex')) return '[Bot] Yandex';
    elseif (strpos($t, 'sogou')) return '[Bot] Sogou';
    elseif (strpos($t, 'exabot')) return '[Bot] Exabot';
    elseif (strpos($t, 'msn')) return '[Bot] MSN';

    // Common Tools and Bots
    elseif (strpos($t, 'mj12bot')) return '[Bot] Majestic';
    elseif (strpos($t, 'ahrefs')) return '[Bot] Ahrefs';
    elseif (strpos($t, 'semrush')) return '[Bot] SEMRush';
    elseif (strpos($t, 'rogerbot') || strpos($t, 'dotbot')) return '[Bot] Moz or OpenSiteExplorer';
    elseif (strpos($t, 'frog') || strpos($t, 'screaming')) return '[Bot] Screaming Frog';

    // Miscellaneous
    elseif (strpos($t, 'facebook')) return '[Bot] Facebook';
    elseif (strpos($t, 'pinterest')) return '[Bot] Pinterest';

    // Check for strings commonly used in bot user agents  
    elseif (
        strpos($t, 'crawler') || strpos($t, 'api') ||
        strpos($t, 'spider') || strpos($t, 'http') ||
        strpos($t, 'bot') || strpos($t, 'archive') ||
        strpos($t, 'info') || strpos($t, 'data')
    ) return '[Bot] Other';

    return 'Other (Unknown)';
}
