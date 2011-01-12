#
# Copyright (c) 2010-2011, FlightAware, LLC
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
#     * Neither the name of FlightAware, LLC nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package require tls


namespace eval ::apns {

    # timeouts for network operations
    variable connect_timeout_ms 5000
    variable write_timeout_ms 2000
    variable feedback_timeout_ms 30000

    # connection details for the gateway server
    variable gateway_host  "gateway.push.apple.com"
    variable gateway_port  2195

    # connection details for the feedback server
    variable feedback_host  "feedback.push.apple.com"
    variable feedback_port  2196

    # filenames of your personal certificate and private-key
    variable certificate   "certificate.pem"
    variable private_key   "private_key.pem"

    # ------

    variable gateway_chan
    variable gateway_signal
    variable feedback_chan
    variable feedback_readbuf
    variable feedback_signal
    variable bad_device_tokens

# --------------------------------------------------
# --------------------------------------------------

# Close the gateway socket.
proc close_apns_gateway {} {
    variable gateway_chan
    logmsg "Closing gateway connection..."
    if {[info exists gateway_chan]} {
        catch { close $gateway_chan }
        unset -nocomplain gateway_chan
    }
}

# Helper callback used to handle reading data when the socket becomes readable.
proc readable_callback_apns_drain {chan signame} {
    if {[eof $chan]} {
        fileevent $chan readable {}
        fileevent $chan writable {}
        logmsg "readable_callback_apns_drain: Closed secure network drain connection due to EOF";
        set $signame -1
        return
    }
    set drained [read $chan]
    if {[string length $drained] != 0} {
        fileevent $chan readable {}
        fileevent $chan writable {}
        logerr "readable_callback_apns_drain: Read unexpected: $drained"
        set $signame -1
        return
    }
    set $signame 1
}

# Helper callback used to handle sending data when the socket becomes writable.
proc writable_callback_apns_handshake {chan signame} {
    if {[catch {tls::handshake $chan} result]} {
        fileevent $chan readable {}
        fileevent $chan writable {}
        logerr "writable_callback_apns_handshake: Error during handshake: $result"
        set $signame -1
        return
    } elseif {$result} {
        fileevent $chan writable {}
        #puts "writable_callback_apns_handshake: Handshake complete"
        array set certinfo [tls::status $chan]
        logmsg "writable_callback_apns_handshake: connected to server with $certinfo(subject)"
        #parray certinfo
        set $signame 1
        return
    } else {
        logmsg "writable_callback_apns_handshake: Handshake still in progress"
    }
}


# Helper callback used to handle sending data when the socket becomes writable.
proc writable_callback_apns_transmit {chan signame payload} {
    fileevent $chan writable {}
    if {[catch {puts -nonewline $chan $payload; flush $chan} result]} {
        logerr "writable_callback_apns_transmit: Error during transmit: $result"
        set $signame -1
    } else {
        puts "debug writable_callback_apns_transmit: Transmit complete"
        set $signame 1
    }
}


# Helper callback used when a read or write operations takes too long.
proc timeout_callback_apns {chan signame} {
    logerr "timeout_callback_apns: Timeout occurred"
    set $signame -1
    catch {fileevent $chan writable {}}
    catch {fileevent $chan readable {}}
}


# Open a connection to the gateway server
# Returns 0 on error.
proc connect_apns_gateway {} {
    variable gateway_chan
    variable gateway_signal
    variable gateway_host
    variable gateway_port
    variable certificate
    variable private_key
    variable connect_timeout_ms

    logmsg "Opening secure gateway connection to $gateway_host:$gateway_port ..."
    set gateway_chan  [tls::socket -async -certfile $certificate -keyfile $private_key $gateway_host $gateway_port]

    # start in binary/blocking mode until the SSL negotiation is finished.
    fconfigure $gateway_chan -encoding binary -buffering none -blocking 1

    # wait for the negotiation to complete or timeout.
    set ::apns::gateway_signal 0
    fileevent $gateway_chan writable [list writable_callback_apns_handshake $gateway_chan ::apns::gateway_signal]
    fileevent $gateway_chan readable [list readable_callback_apns $gateway_chan ::apns::gateway_signal]
    set afterID [after $connect_timeout_ms timeout_callback_apns $gateway_chan ::apns::gateway_signal]
    vwait ::apns::gateway_signal

    after cancel $afterID
    fileevent $gateway_chan readable {}
    fileevent $gateway_chan writable {}

    #puts "connect_apns_gateway: done connecting, status $::apns::gateway_signal"

    if {$::apns::gateway_signal < 0} {
        close_apns_gateway
        return 0
    }

    # switch to non-blocking mode.
    fconfigure $gateway_chan -blocking 0
    return 1
}


# Connect to the gateway server, but only if not already connected
# Returns 0 on error, 1 on success (already connected or connect succeeded).
proc connect_apns_gateway_ifneeded {} {
    variable gateway_chan

    # if no socket, then try to open one.
    if {![info exists gateway_chan]} {
        return [connect_apns_gateway]
    }

    # already have connection, so assume it is good.
    return 1
}

# Send an alert to the gateway service.
# Throws error on transmit failure.
proc send_apns {deviceToken payload} {
    variable gateway_chan
    variable gateway_signal
    variable write_timeout_ms

    # make sure it isn't too long.
    if {[string length $deviceToken] > 64 || [string length $deviceToken] % 2 != 0 || [string length $deviceToken] == 0} {
        error "send_apns: invalid deviceToken"
    }
    if {[string length $payload] > 256} {
        error "send_apns: too long"
    }

    # format the outgoing network packet.
    # message format is, |COMMAND|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD|

    # method 1
    #set formatstr [format "cSH%dSa%d" [string length $deviceToken] [string bytelength $payload]]
    #set msg [binary format $formatstr 0 [expr [string length $deviceToken]/2] $deviceToken [string bytelength $payload] [encoding convertto utf-8 $payload]]

    # method 2
    #set msg [binary format "cSH*Sa*" 0 [expr [string length $deviceToken]/2] $deviceToken [string bytelength $payload] [encoding convertto utf-8 $payload]]

    # method 3
    set msg [binary format "cSH*Sa*" 0 [expr [string length $deviceToken]/2] $deviceToken [string length $payload] $payload]

    binary scan $msg "H*" hexmsg
    puts "debug outgoing message: $hexmsg"

    # send the packet.
    for {set retry 0} {$retry<10} {incr retry} {
        if {[catch {
            # connect if needed.
            if {![connect_apns_gateway_ifneeded]} {
                error "send_apns: failed to connect"
            }

            # wait for the  to complete or timeout.
            set ::apns::gateway_signal 0
            fileevent $gateway_chan writable [list writable_callback_apns_transmit $gateway_chan ::apns::gateway_signal $msg]
            fileevent $gateway_chan readable [list readable_callback_apns_drain $gateway_chan ::apns::gateway_signal]
            set afterID [after $write_timeout_ms timeout_callback_apns $gateway_chan ::apns::gateway_signal)]
            vwait ::apns::gateway_signal

            # cleanup after waiting.
            after cancel $afterID
            fileevent $gateway_chan readable {}
            fileevent $gateway_chan writable {}

            if {$::apns::gateway_signal != 1} {
                error "send_apns: send failure, got $::apns::gateway_signal"
            }
        } result] == 1} {
            logerr "send_apns: Error occurred: $result"
            close_apns_gateway
        } else {
            logmsg "send_apns: Successfully sent"
            return 1
        }

    }
    error "send_apns: failed after 10 retries"
}


# --------------------------------------------------
# --------------------------------------------------

# Close the feedback socket.
proc close_apns_feedback {} {
    variable feedback_chan
    logmsg "Closing feedback connection..."
    if {[info exists feedback_chan]} {
        catch { close $feedback_chan }
        unset -nocomplain feedback_chan
    }
}


# Helper callback used to read data when the feedback socket becomes readable.
proc readable_callback_apns_feedback {chan signame} {
    variable feedback_readbuf

    if {[eof $chan]} {
        logmsg "readable_callback_apns_feedback: Closed secure network feedback connection due to EOF";
        fileevent $chan readable {}
        fileevent $chan writable {}
        set $signame 1
        return
    }
    if {[string length $feedback_readbuf] < 6} {
        # read enough to interpret the header
        set readamt [expr 6-[string length $feedback_readbuf]]
        append feedback_readbuf [read $chan $readamt]
    }
    if {[string length $feedback_readbuf] >= 6} {
        # parse the header and compute the total message size.
        if {[binary scan $feedback_readbuf "IuSu" timestamp tokenlen] != 2} {
            logerr "readable_callback_apns_feedback: Parse failure reading secure network connection";
            fileevent $chan readable {}
            fileevent $chan writable {}
            set $signame -1
            return
        }
        set msgsize [expr 6+$tokenlen]
        #puts "debug: Whole message size will be $msgsize (have [string length $feedback_readbuf] now)"

        # read enough to get the entire message
        if {[string length $feedback_readbuf] < $msgsize} {
            set readamt [expr $msgsize-[string length $feedback_readbuf]]
            append feedback_readbuf [read $chan $readamt]
        }

        # if we have an entire message, then parse it.
        if {[string length $feedback_readbuf] >= $msgsize} {
            set formatstr [format "IuSuH%da*" [expr 2*$tokenlen]]
            if {[binary scan $feedback_readbuf $formatstr timestamp tokenlen device_token feedback_readbuf] != 4} {
                logerr "readable_callback_apns_feedback: Parse failure reading secure network connection"
                fileevent $chan readable {}
                fileevent $chan writable {}
                set $signame -1
                return
            }

            # excellent, we have parsed an entire message.
            logmsg "Got bounce feedback [clock format $timestamp -format {%Y-%m-%d %H:%M:%S} -timezone :UTC] for $device_token"
            if {[lsearch -exact $bad_device_tokens $device_token] == -1} {
                lappend bad_device_tokens $device_token
            }
        }
    }
}


# Connect to the feedback server, reading any responses, and then disconnect.
# Appends the responses to ::apns::bad_device_tokens
# Returns 0 on error.
proc connect_and_receive_apns_feedback {} {
    variable bad_device_tokens
    variable feedback_chan
    variable feedback_readbuf
    variable feedback_host
    variable feedback_port
    variable certificate
    variable private_key 
    variable connect_timeout_ms
    variable feedback_timeout_ms

    if {![info exists bad_device_tokens]} {
        set bad_device_tokens {}
    }

    # open new connection
    logmsg "Opening secure feedback connection to $feedback_host:$feedback_port ..."
    set feedback_chan  [tls::socket -async -certfile $certificate -keyfile $private_key $feedback_host $feedback_port]

    # start in binary/blocking mode until the SSL negotiation is finished.
    fconfigure $feedback_chan -encoding binary -buffering none -blocking 1

    # wait for the negotiation to complete or timeout.
    set ::apns::feedback_signal 0
    set feedback_readbuf {}
    fileevent $feedback_chan writable [list writable_callback_apns_handshake $feedback_chan ::apns::feedback_signal]
    fileevent $feedback_chan readable [list readable_callback_apns_feedback $feedback_chan ::apns::feedback_signal]
    set afterID [after $connect_timeout_ms [list timeout_callback_apns $feedback_chan ::apns::feedback_signal]]
    logmsg "Waiting for feedback_signal"
    vwait ::apns::feedback_signal

    after cancel $afterID
    fileevent $feedback_chan readable {}
    fileevent $feedback_chan writable {}

    logmsg "Finished waiting"

    if {$::apns::feedback_signal < 0} {
        close_apns_feedback
        return 0
    }

    logmsg "Reading from feedback"

    # switch to non-blocking mode and wait until timeout or EOF.
    set ::apns::feedback_signal 0
    fconfigure $feedback_chan -blocking 0
    fileevent $feedback_chan readable [list readable_callback_apns_feedback $feedback_chan ::apns::feedback_signal]
    set afterID [after $feedback_timeout_ms [list timeout_callback_apns $feedback_chan ::apns::feedback_signal]]
    vwait ::apns::feedback_signal

    # done with connection so close it
    close_apns_feedback

    if {$::apns::feedback_signal < 0} {
        return 0
    }
    return 1
}


# --------------------------------------------------
# --------------------------------------------------

}
