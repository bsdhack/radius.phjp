# radius.php

php から radius にアクセスするための関数です。  

Radius についての詳細は RFC2138 を参照して下さい。  
ただし、RFC2138 に完全に準拠した実装ではありません。  
自分が必要とした機能のみを実装しています。  

php の関数として実装してありますので、radius.php を require して radiusauth() をコールします。
radiusauth() には以下のパラメタを指定します。 詳しくはソースコードのコメントを参照して下さい


* *radius_server* 	radius サーバ
* *radius_port* 	radius サーバのポート
* *radius_id* 	ユーザID
* *radius_passwd* 	パスワード
* *radius_key* 	共有鍵
* *radius_retry* 	再送回数
* *radius_timeout* 	タイムアウト秒数
* *ipaddr* 	自分自身の IPアドレス 
