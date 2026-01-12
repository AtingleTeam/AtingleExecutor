--[[
    Atingle init.lua
--]]

local getgenv = getgenv or function() return _G end
local env = getgenv()

local HttpService = game:GetService("HttpService")
local CoreGui = game:GetService("CoreGui")

local function protect(fn)
    return (newcclosure or function(f) return f end)(fn)
end

local api = {
    getgenv = getgenv,
    getrenv = getrenv or function() return game end,
    getreg  = getreg  or function() return debug.getregistry() end,
    getgc   = getgc   or function() return debug.getgc() end,
    getsenv = getsenv or function(_) return nil end,
    getfenv = getfenv or function(_) return nil end,
    setfenv = setfenv or function(_, _) end,
    getcallingscript = getcallingscript or function() return nil end,
    
    hookfunction   = hookfunction   or function(_, new) return new end,
    newcclosure    = newcclosure    or function(fn) return fn end,
    replaceclosure = replaceclosure or function(_, new) return new end,
    checkcaller    = checkcaller    or function() return false end,
    
    mouse1click  = mouse1click  or function() end,
    mouse1press  = mouse1press  or function() end,
    mouse1release = mouse1release or function() end,
    mouse2click  = mouse2click  or function() end,
    mouse2press  = mouse2press  or function() end,
    mouse2release = mouse2release or function() end,
    mousemoverel = mousemoverel or function(_, _) end,
    mousemoveabs = mousemoveabs or function(_, _) end,
    keypress     = keypress     or function(_) end,
    keyrelease   = keyrelease   or function(_) end,

    protect_gui  = protectgui   or function(gui) return gui end,
    setclipboard = setclipboard or function(text) warn("[setclipboard] Not Currently available") end,
}

env.debug = env.debug or {}
local debug_lib = {
    getupvalue    = debug.getupvalue    or function() end,
    setupvalue    = debug.setupvalue    or function() end,
    getinfo       = debug.getinfo       or function() end,
    getconstants  = debug.getconstants  or function() return {} end,
    getproto      = debug.getproto      or function() end,
    getprotos     = debug.getprotos     or function() return {} end,
    setconstant   = debug.setconstant   or function() end,
}

for name, fn in pairs(debug_lib) do
    env.debug[name] = fn
    env[name] = fn
end

env.request = request or http_request or function(opts)
	if type(opts) ~= "table" or not opts.Url then
		return { StatusCode = 400, Body = "invalid request" }
	end

	local ok, result = pcall(function()
		if opts.Method == "POST" then
			return HttpService:PostAsync(opts.Url, opts.Body or "")
		else
			return HttpService:GetAsync(opts.Url)
		end
	end)

	return {
		StatusCode = ok and 200 or 500,
		Body = ok and result or "request failed"
	}
end

env.http_get = function(url)
	local ok, res = pcall(function()
		return HttpService:GetAsync(url)
	end)
	return ok and res or nil
end

env.gethui = gethui or function()
    local core = game:GetService("CoreGui")
    for _, gui in ipairs(core:GetChildren()) do
        if gui:IsA("ScreenGui") then
            return gui
        end
    end
    return core
end

env.reverse_string = function(str)
    return str:reverse()
end

local Event = {}
Event.__index = Event

function Event.new()
    local self = setmetatable({}, Event)
    self._event = Instance.new("BindableEvent")
    return self
end

function Event:connect(callback)
    return self._event.Event:Connect(callback)
end

function Event:fire(...)
    self._event:Fire(...)
end

env.Event = Event

for name, func in pairs(api) do
    if not env[name] then
        env[name] = func
    end
end
