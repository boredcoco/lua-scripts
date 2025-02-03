-- Title: Telnet Version Detection Script
-- Description: This script connects to a Telnet service and attempts to retrieve the version information from the banner.
-- Author: Your Name
-- Date: 2025

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

-- Define the portrule function to trigger the script for port 23 (Telnet)
portrule = function(host, port)
    return port.number == 23 and port.protocol == "tcp"  -- Trigger on TCP port 23 (Telnet)
end

-- Function to retrieve Telnet banner and version
local function get_telnet_version(host, port)
    local socket_obj = nmap.new_socket()  -- Create a new socket using Nmap's method
    socket_obj:set_timeout(5000)  -- Timeout set to 5 seconds (5000 ms)

    -- Try connecting to the target via Telnet port (usually port 23)
    local success, err = socket_obj:connect(host.ip, port)
    if success then
        stdnse.print_debug(1, "Connected to " .. host.ip .. " on port " .. port.number)  -- Debug: connection success

        -- Try receiving the initial banner message from the Telnet server
        local response, err = socket_obj:receive(1024)  -- Receive up to 1024 bytes
        if response then
            stdnse.print_debug(1, "Received banner: " .. response)  -- Debug: banner received

            -- Check for version information in the banner
            local version = string.match(response, ".*Telnet (.+)\r\n")  -- Match the Telnet version (common format)
            if version then
                return version  -- Return the version string if found
            else
                return "No version info found"  -- Return if no version info is detected
            end
        else
            return "No response from Telnet service"  -- No banner received
        end
    else
        return "Failed to connect: " .. (err or "Unknown error")  -- Connection failed, print error message
    end
end

-- Script entry point
action = function(host, port)
    -- Check if the port is 23 (Telnet)
    if port.protocol == "tcp" and port.number == 23 then
        local version = get_telnet_version(host, port.number)
        if version then
            return "Telnet version: " .. version
        else
            return "Could not retrieve Telnet version."
        end
    else
        return nil  -- Skip if not Telnet port
    end
end
