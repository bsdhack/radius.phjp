<?
	/*
	 * All rights reserved, copyright (c) 2007, Mitzyuki IMAIZUMI
	 * $Id: Radius.php,v 1.1 2005/05/07 09:20:02 mitz Exp $
	 */

	/*
	 * Radius 認証関数
	 *	Radius についての詳細は RFC2138 を参照
	 *	但し RFC2138 を完全に実装はしていない
	 *	認証許可パケットの属性値は Session-Timeout(27) 以外は無視する
	 *
	 *	引数配列には以下の構成要素が必須
	 *		"radius_server" => radius サーバのホスト名/IPアドレス
	 *		"radius_port" => radius サーバのポート
	 *		"radius_id" => ユーザID
	 *		"radius_passwd" => パスワード
	 *		"radius_key" => 共有鍵
	 *		"radius_retry" => 再送回数
	 *		"radius_timeout" => タイムアウト
	 *		"ipaddr" => IP アドレス
	 *
	 *	以下の値をリターンする
	 *		>= 0 : 認証成功(有効期間秒)
	 *		-1   : 認証失敗
	 *		-2   : タイムアウト
	 *		-3   : ネットワークエラー
	 *		-4   : パラメタ不正
	 */

	define("ACCESS_REJECT", 3);
	define("HEADER_LEN", 20);
	define("ATTRIB_SESSION_TIMEOUT", 27);

    function radiusauth($values){

		/* パラメタチェック */
		foreach(array(
			"radius_server",
			"radius_port",
			"radius_id",
			"radius_passwd",
			"radius_key",
			"radius_retry",
			"radius_timeout",
			"ipaddr") as $key)
			if(ereg("^[[:space:]]*$", $values[$key]))
				return(-4);

		/* NAS アドレス */
		$nas = explode(".", $values["ipaddr"]);

		/* Radius server */
		if(!$server = gethostbyname($values["radius_server"]))
			return(-3);

		/* socket 作成 */
		if(!$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP))
			return(-3);

		/* Authenticator */
		srand(microtime() * 1000000);
		for($i=0; $i<16; $i++)
			$code .= pack("C", rand(1, 255));

		/* password 暗号化 */
		$pass = encrypt($values["radius_passwd"], $values["radius_key"], $code);

		/* packet 長セット */
		$len = 
			4 +											/* header */
			strlen($code) +								/* authcode */
			6 +											/* service type */
			2 + strlen($values["radius_id"]) +			/* username */
			2 + strlen($pass) +							/* password */
			6 +											/* NAS IP */
			6;											/* NAS Port */

		/* packet 作成 */
		$id = rand(1, 255);

		/*            H  A S  I   P   IP    PORT
		              v  v v  v   v   v     v    */
		$data = pack("CCna*CCNCCa*CCa*CCCCCCCCCCCC",
			1, $id, $len,								/* header */
			$code,										/* authcode */
			6, 6, 1,									/* service type */
			1, 2 + strlen($values["radius_id"]), $values["radius_id"],
			2, 2 + strlen($pass), $pass,				/* password */
			4, 6, $nas[0], $nas[1], $nas[2], $nas[3],	/* NAS IP */
			5, 6, 0, 0, 0, 0							/* NAS Port */
	    );

		/*
		 * packet 再送処理
		 */
		$count = 0;
		while(1){
			/*
			 * socket_sendto() は EXPERIMENTAL ステータスであるが
			 * socket_select() が socket_write() だと正常に動作しないので使用
			 */
			socket_sendto($sock, $data, $len, 0,
				$server, $values["radius_port"]);

			/* timeout 処理 */
			if(($enable = socket_select($set = array($sock), $w=null, $e=null, 
				$values["radius_timeout"])) === false){
				socket_close($sock);
				return(-3);
			}
			else if($enable > 0)
				break;
			else
				if($count++ >= $values["radius_retry"]){
					socket_close($sock);
					return(-2);
				}
		}

		/* 認証応答受信 */
		socket_recvfrom($sock, $data, 4096, 0, $server, $values["radius_port"]);
		socket_close($sock);

		/* packet 解析 */
		$val = unpack("Ccode/Cid/nlen/a16auth/A*data", $data);

		/* Access Reject */
		if($val["code"] == ACCESS_REJECT)
			return(-1);

		/* Attribute 解析 */
		$packetlen = $val["len"] - HEADER_LEN;
		while($packetlen > 0){
			/* type、length 取得 */
			$val = unpack("Ctype/Clen/A*data", $val["data"]);
			$packetlen -= $val["len"];
			if(($type = $val["type"]) == ATTRIB_SESSION_TIMEOUT){
				/* Session timeout の場合は u_long で秒を取得 */
				$val = unpack("Nvalue/A*data", $val["data"]);

				return($val[value]);

			}
			else{
				/* それ以外の属性はスキップ */
				$len = $val["len"] - 2;
				$val = unpack("A{$len}value/A*data", $val["data"]);
			}
		}

		return(0);

	}

    function encrypt($password, $key, $code)
	{

		/* MD5 は 32bit 固定 */
		$sum = md5($key . $code);
		/* パスワードが 16 bytes 以下の場合は NULL で埋める */
		$pass = pack("a16", $password);

		/* 暗号化アルゴリズムは RFC2138 P.22 参照 */
		for($i=0; $i<16; $i++)
			$output .= chr((hexdec(substr($sum, $i * 2, 2))) ^
							(ord(substr($pass, $i, 1))));

		return($output);

    }

?>
