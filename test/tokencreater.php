<?php
    main();
    function main(){
        $tokenheaderarray = [
            "alg"=> "HS256",
            "typ"=> "JWT",
        ];
        $tokenplayloadarray = [
            "exp"=> 1696868424,
            "role" => "ADMIN",
            "id"=> 1,
            "userName"=> "Admin"
        ];

        $tokenheader = json_encode($tokenheaderarray);
        $tokenplayload = json_encode($tokenplayloadarray);
        $newtoken = tokencreater($tokenheader,$tokenplayload,"zxc82456");
        $result = tokenchecker($newtoken);
        if($result){
            echo "active";
        }else{
            echo "unactive";
        }
    }

    function tokenchecker($token){
        $parts = explode('.',$token);
        $tokenheader = $parts[0];
        $tokenplayload = $parts[1];
        $tokensignature = $parts[2];
        $tokendata = $tokenheader . "." . $tokenplayload;
        $tokenplayloadjson = base64_decode($tokenplayload);
        $tokenplayloadarray = json_decode($tokenplayloadjson,true);
        $tokenrealkey = _keycreater("zxc82456");
        $currentsignature = _tokensignature($tokendata, $tokenrealkey);
        if($tokensignature == $currentsignature){
            //接下來，驗證時間，因為生成Token跟驗證Token都是在服務器出來的，所以我們不需要處理時區問題
            //1.解碼playlod並取得Token的UnixTime
            $tokenplayloadjson = base64_decode($tokenplayload);
            $tokenplayloadarray = json_decode($tokenplayloadjson,true);
            $tokenexp = $tokenplayloadarray['exp'];
            //2.拿當前時間跟UnixTime去做相減找出時差
            $nowunixtime = time();
            $timediff = $nowunixtime - $tokenexp;
            //3.將時差與指定期限做比較來驗證是否有效，unixtime一小時是3600
            if($timediff > 3*3600){
                return false;
            }else{
                return true;
            }

        }else{
            return false;
        }

    }

    function tokencreater($headerjson,$playloadjson,$passwd){
        //json轉Base64，並用成我所需要的字串
        $headerbase = base64_encode($headerjson);
        $playloadbase = base64_encode($playloadjson);
        $tokendata = $headerbase . "." . $playloadbase;
        $tokenkey = _keycreater($passwd);
        $tokensignature = _tokensignature($tokendata,$tokenkey);
        return $tokendata . "." . $tokensignature;
    }

    function _tokensignature($tokendata,$tokenrealkey){
        //這個網頁主要使用的HS256
        $signaturestring = hash_hmac('sha256', $tokendata, $tokenrealkey, true);
        $signature_base64 = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signaturestring));
        return $signature_base64;
    }

    function _keycreater($passwd){
        $hashname = apache_getenv('KEYCalName');
        $pubkey = apache_getenv('JWT_SECRET_KEY');
        $realkey = hash_hmac($hashname,$pubkey,$hashname);
        return $realkey;
    }

?>