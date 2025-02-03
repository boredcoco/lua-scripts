-- Title: Telnet Version Detection Script
-- Description: This script connects to a Telnet service and retrieves the version information from the banner.
-- Author: Your Name
-- Date: 2025

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

-- Define the portrule function to trigger the script for port 23 (Telnet)
portrule = function(host, port)
    return port.number == 23 and port.protocol == "tcp"  -- Trigger on TCP port 23 (Telnet)
end

-- Function to retrieve Telnet version from the banner
local function get_telnet_version(host, port)
    -- Ensure host and port are valid
    if not host or not host.ip then
        return "Invalid host or IP address"
    end
    if not port or not port.number then
        return "Invalid port number"
    end

    local socket_obj = nmap.new_socket()  -- Create a new socket using Nmap's method
    socket_obj:set_timeout(5000)  -- Timeout set to 5 seconds (5000 ms)

    -- Try connecting to the target via Telnet port (usually port 23)
    local success, err = socket_obj:connect(host.ip, port.number)
    if not success then
        return "Failed to connect: " .. (err or "Unknown error")  -- Connection failed, print error message
    end

    stdnse.print_debug(1, "Connected to " .. host.ip .. " on port " .. port.number)  -- Debug: connection success

    -- Receive the banner or prompt from the Telnet server
    local response, err = socket_obj:receive(1024)  -- Receive up to 1024 bytes
    if not response then
        return "No response from Telnet service: " .. (err or "Unknown error")
    end
    stdnse.print_debug(1, "Received banner: " .. response)  -- Debug: banner received

    -- Try to extract version information from the banner
    local version = string.match(response, ".*Telnet (.+)\r\n")  -- Match Telnet version in the format "Telnet <version>"
    if version then
        return "Telnet version: " .. version  -- Return the extracted version
    else
        return "No Telnet version found in banner"  -- No version info found
    end
end

-- Script entry point
action = function(host, port)
    -- Ensure the port is 23 (Telnet)
    if port.protocol == "tcp" and port.number == 23 then
        local version = get_telnet_version(host, port)
        return version
    else
        return nil  -- Skip if not Telnet port
    end
end
