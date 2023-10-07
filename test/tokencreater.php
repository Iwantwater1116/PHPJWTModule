<?php
    main();
    function main(){
        $tokenheaderarray = [
            "alg"=> "HS256",
            "typ"=> "JWT",
        ];
        $tokenplayloadarray = [
            "exp"=> 1696521836,
            "role" => "ADMIN",
            "userId"=> 1,
            "userName"=> "Admin"
        ];

        $tokenheader = json_encode($tokenheaderarray);
        $tokenplayload = json_encode($tokenplayloadarray);
        $tokenkey = "zxc82456";
        $newtoken = tokencreater($tokenheader,$tokenplayload,$tokenkey);
        $result = tokenchecker($newtoken,"zxc82456");
        if($result){
            echo "active";
        }else{
            echo "unactive";
        }
    }

    function tokenchecker($token,$tokenrealkey){
        $parts = explode('.',$token);
        $tokenheader = $parts[0];
        $tokenplayload = $parts[1];
        $tokensignature = $parts[2];
        $tokendata = $tokenheader . "." . $tokenplayload;
        $currentsignature = _tokensignature($tokendata, $tokenrealkey);
        if($tokensignature == $currentsignature){
            return true;
        }else{
            return false;
        }

    }

    function tokencreater($headerjson,$playloadjson,$tokenrealkey){
        //json轉Base64，並用成我所需要的字串
        $headerbase = base64_encode($headerjson);
        $playloadbase = base64_encode($playloadjson);
        $tokendata = $headerbase . "." . $playloadbase;
        $tokensignature = _tokensignature($tokendata,$tokenrealkey);
        return $tokendata . "." . $tokensignature;
    }

    function _tokensignature($tokendata,$tokenrealkey){
        //這個網頁主要使用的HS256
        $signaturestring = hash_hmac('sha256', $tokendata, $tokenrealkey, true);
        $signature_base64 = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signaturestring));
        return $signature_base64;
    }

?>