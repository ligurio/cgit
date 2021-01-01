-- This script may be be used with the testres-filter or repo.testres-filter
-- settings in cgitrc with the `lua:` prefix.
-- It formats test report in Test Anything Protocol v13 to HTML.
-- It is designed to be used with the lua.

function filter_open(email, page)
	buffer = ""
	md5 = md5_hex(email:sub(2, -2):lower())
end

function filter_close()
	html("<img src='//www.gravatar.com/avatar/" .. md5 .. "?s=13&amp;d=retro' width='13' height='13' alt='Gravatar' /> " .. buffer)
	return 0
end

function filter_write(str)
	buffer = buffer .. str
end
