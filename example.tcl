#!/usr/local/bin/tclsh8.5


source apns.tcl


set ::apns(connect_timeout_ms) 5000
set ::apns(write_timeout_ms) 2000
set ::apns(feedback_timeout_ms) 30000
set ::apns(feedback_connect_period) 600

if {1} {
    # for development, use Apple's sandbox servers.
    # Messages will still get delivered, but Apple is less paranoid about misbehaving or abusive 
    set ::apns(gateway_host)  gateway.sandbox.push.apple.com
    set ::apns(gateway_port)  2195

    set ::apns(feedback_host) feedback.sandbox.push.apple.com
    set ::apns(feedback_port) 2196

    set ::apns(certificate)   apns-sandbox.crt
    set ::apns(private_key)   apns-sandbox.key

} else {
    # for production, use Apple's real servers.
    set ::apns(gateway_host)  gateway.push.apple.com
    set ::apns(gateway_port)  2195
    
    set ::apns(feedback_host) feedback.push.apple.com
    set ::apns(feedback_port) 2196
    
    set ::apns(certificate)   apns-production.crt
    set ::apns(private_key)   apns-production.key
}

# A simple logging proc.
# In a real service, you might want to make this write to syslog or something.
proc logmsg {msg} {
    puts $msg
}

# A simple logging proc.
# In a real service, you might want to make this write to syslog or something.
proc logerr {msg} {
    puts stderr $msg
}


proc main {} {

    # send a message to a few arbitrary deviceTokens.
    # In a real service, this would probably involve a SELECT from your database.
    for {set i 0} {$i < 10} {incr i} {
        set json "{\"aps\": \"hello message $i\"}"
        set deviceToken "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF$i"
        send_apns $deviceToken $json
        logmsg "sent"
        after 1000
        logmsg "looping"
    }
    
    # wait for a little bit for the Feedback server.
    logmsg "Sleeping..."
    after 5000

    # check with the Feedback server to see if there were any bounced devices.
    # In a real service, you would mark the devices as bad in your database and not send future messages.
    connect_and_receive_apns_feedback
    if {[llength $::apns(bad_device_tokens)] > 0} {
        logmsg "have [llength $::apns(bad_device_tokens)] waiting device_tokens"
    } else {
        logmsg "no bad_device_tokens waiting"
    }
}


main
