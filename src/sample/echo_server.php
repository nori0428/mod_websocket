<?php
require_once 'ext/Server.php';
require_once 'ext/Server/Handler.php';
 
class Net_Server_Handler_Talkback extends Net_Server_Handler {
    function onConnect($clientId = 0) {
        $this->_server->sendData($clientId, "[quit] to exit\r\n");
    }
    function onReceiveData($clientId = 0, $data = '') {
        $data = trim($data);
        if($data=='') return;
        switch($data) {
            case "quit":
                $this->_server->sendData($clientId, "Bye!");
                $this->_server->closeConnection($clientId);
                break;
            default:
                $this->_server->sendData($clientId, $data);
                break;
        }
    }
}

$server = &Net_Server::create('Multiprocess', "127.0.0.1", 8080);
$server->setMaxClients(1);
$server->_debug = false;
$handler = &new Net_Server_Handler_Talkback();
$server->setCallbackObject($handler);
$server->start();
?>
