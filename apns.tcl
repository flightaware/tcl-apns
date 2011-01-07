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

# set ::apns(connect_timeout_ms) 5000
# set ::apns(write_timeout_ms) 2000
# set ::apns(feedback_timeout_ms) 30000
# set ::apns(feedback_connect_period) 600

# set ::apns(gateway_host)  gateway.push.apple.com
# set ::apns(gateway_port)  2195

# set ::apns(feedback_host) feedback.push.apple.com
# set ::apns(feedback_port) 2196

# set ::apns(certificate)   apns-production.crt
# set ::apns(private_key)   apns-production.key

# --------------------------------------------------
# --------------------------------------------------

proc close_apns_gateway {} {
    logmsg "Closing gateway connection..."
    if {[info exists ::apns(gateway_chan)]} {
        catch { close $::apns(gateway_chan) }
        unset -nocomplain ::apns(gateway_chan)
    }
}

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
        logerr "readable_callback_apns_drain: Read unexpected: {$drained}"
        set $signame -1
        return
    }
    set $signame 1
}

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


proc timeout_callback_apns {chan signame} {
    logerr "timeout_callback_apns: Timeout occurred"
    set $signame -1
    catch {fileevent $chan writable {}}
    catch {fileevent $chan readable {}}
}


# Returns 0 on error.
proc connect_apns_gateway {} {
    logmsg "Opening secure gateway connection to $::apns(gateway_host):$::apns(gateway_port)..."
    set ::apns(gateway_chan)  [tls::socket -async -certfile $::apns(certificate) -keyfile $::apns(private_key) $::apns(gateway_host) $::apns(gateway_port)]

    # start in binary/blocking mode until the SSL negotiation is finished.
    fconfigure $::apns(gateway_chan) -encoding binary -buffering none -blocking 1

    # wait for the negotiation to complete or timeout.
    set ::apns(gateway_signal) 0
    fileevent $::apns(gateway_chan) writable [list writable_callback_apns_handshake $::apns(gateway_chan) ::apns(gateway_signal)]
    fileevent $::apns(gateway_chan) readable [list readable_callback_apns $::apns(gateway_chan) ::apns(gateway_signal)]
    set afterID [after $::apns(connect_timeout_ms) timeout_callback_apns $::apns(gateway_chan) ::apns(gateway_signal)]
    vwait ::apns(gateway_signal)

    after cancel $afterID
    fileevent $::apns(gateway_chan) readable {}
    fileevent $::apns(gateway_chan) writable {}

    #puts "connect_apns_gateway: done connecting, status $::apns(gateway_signal)"

    if {$::apns(gateway_signal) < 0} {
        close_apns_gateway
        return 0
    }

    # switch to non-blocking mode.
    fconfigure $::apns(gateway_chan) -blocking 0
    return 1
}


# Returns 0 on error.
proc connect_apns_gateway_ifneeded {} {
    # if no socket, then try to open one.
    if {![info exists ::apns(gateway_chan)]} {
        return [connect_apns_gateway]
    }

    # already have connection, so assume it is good.
    return 1
}

# Send an alert to the gateway service.
# Throws error on transmit failure.
proc send_apns {deviceToken payload} {

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
            set ::apns(gateway_signal) 0
            fileevent $::apns(gateway_chan) writable [list writable_callback_apns_transmit $::apns(gateway_chan) ::apns(gateway_signal) $msg]
            fileevent $::apns(gateway_chan) readable [list readable_callback_apns_drain $::apns(gateway_chan) ::apns(gateway_signal)]
            set afterID [after $::apns(write_timeout_ms) timeout_callback_apns $::apns(gateway_chan) ::apns(gateway_signal)]
            vwait ::apns(gateway_signal)

            # cleanup after waiting.
            after cancel $afterID
            fileevent $::apns(gateway_chan) readable {}
            fileevent $::apns(gateway_chan) writable {}

            if {$::apns(gateway_signal) != 1} {
                error "send_apns: send failure, got $::apns(gateway_signal)"
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

proc close_apns_feedback {} {
    logmsg "Closing feedback connection..."
    if {[info exists ::apns(feedback_chan)]} {
        catch { close $::apns(feedback_chan) }
        unset -nocomplain ::apns(feedback_chan)
    }
}


proc readable_callback_apns_feedback {chan signame} {
    if {[eof $chan]} {
        logmsg "readable_callback_apns_feedback: Closed secure network feedback connection due to EOF";
        fileevent $chan readable {}
        fileevent $chan writable {}
        set $signame 1
        return
    }
    if {[string length $::apns(feedback_readbuf)] < 6} {
        # read enough to interpret the header
        set readamt [expr 6-[string length $::apns(feedback_readbuf)]]
        append ::apns(feedback_readbuf) [read $chan $readamt]
    }
    if {[string length $::apns(feedback_readbuf)] >= 6} {
        # parse the header and compute the total message size.
        if {[binary scan $::apns(feedback_readbuf) "IuSu" timestamp tokenlen] != 2} {
            logerr "readable_callback_apns_feedback: Parse failure reading secure network connection";
            fileevent $chan readable {}
            fileevent $chan writable {}
            set $signame -1
            return
        }
        set msgsize [expr 6+$tokenlen]
        #puts "debug: Whole message size will be $msgsize (have [string length $::apns(feedback_readbuf)] now)"

        # read enough to get the entire message
        if {[string length $::apns(feedback_readbuf)] < $msgsize} {
            set readamt [expr $msgsize-[string length $::apns(feedback_readbuf)]]
            append ::apns(feedback_readbuf) [read $chan $readamt]
        }

        # if we have an entire message, then parse it.
        if {[string length $::apns(feedback_readbuf)] >= $msgsize} {
            set formatstr [format "IuSuH%da*" [expr 2*$tokenlen]]
            if {[binary scan $::apns(feedback_readbuf) $formatstr timestamp tokenlen device_token ::apns(feedback_readbuf)] != 4} {
                logerr "readable_callback_apns_feedback: Parse failure reading secure network connection";
                fileevent $chan readable {}
                fileevent $chan writable {}
                set $signame -1
                return
            }

            # excellent, we have parsed an entire message.
            logmsg "Got bounce feedback [clock format $timestamp -format {%Y-%m-%d %H:%M:%S} -timezone :UTC] for $device_token"
            if {[lsearch -exact $::apns(bad_device_tokens) $device_token] == -1} {
                lappend ::apns(bad_device_tokens) $device_token
            }
        }
    }
}


# Returns 0 on error.
proc connect_and_receive_apns_feedback {} {
    if {![info exists ::apns(bad_device_tokens)]} {
        set ::apns(bad_device_tokens) {}
    }

    # open new connection
    logmsg "Opening secure feedback connection to $::apns(feedback_host):$::apns(feedback_port)..."
    set ::apns(feedback_chan)  [tls::socket -async -certfile $::apns(certificate) -keyfile $::apns(private_key) $::apns(feedback_host) $::apns(feedback_port)]

    # start in binary/blocking mode until the SSL negotiation is finished.
    fconfigure $::apns(feedback_chan) -encoding binary -buffering none -blocking 1

    # wait for the negotiation to complete or timeout.
    set ::apns(feedback_signal) 0
    set ::apns(feedback_readbuf) {}
    fileevent $::apns(feedback_chan) writable [list writable_callback_apns_handshake $::apns(feedback_chan) ::apns(feedback_signal)]
    fileevent $::apns(feedback_chan) readable [list readable_callback_apns_feedback $::apns(feedback_chan) ::apns(feedback_signal)]
    set afterID [after $::apns(connect_timeout_ms) [list timeout_callback_apns $::apns(feedback_chan) ::apns(feedback_signal)]]
    logmsg "Waiting for feedback_signal"
    vwait ::apns(feedback_signal)

    after cancel $afterID
    fileevent $::apns(feedback_chan) readable {}
    fileevent $::apns(feedback_chan) writable {}

    logmsg "Finished waiting"

    if {$::apns(feedback_signal) < 0} {
        close_apns_feedback
        return 0
    }

    logmsg "Reading from feedback"

    # switch to non-blocking mode and wait until timeout or EOF.
    set ::apns(feedback_signal) 0
    fconfigure $::apns(feedback_chan) -blocking 0
    fileevent $::apns(feedback_chan) readable [list readable_callback_apns_feedback $::apns(feedback_chan) ::apns(feedback_signal)]
    set afterID [after $::apns(feedback_timeout_ms) [list timeout_callback_apns $::apns(feedback_chan) ::apns(feedback_signal)]]
    vwait ::apns(feedback_signal)

    # done with connection so close it
    close_apns_feedback

    if {$::apns(feedback_signal) < 0} {
        return 0
    }
    return 1
}


# --------------------------------------------------
# --------------------------------------------------

