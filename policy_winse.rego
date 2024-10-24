package lightbulbs

import rego.v1

default allow_winse = false

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "winse" in input.uri_args
	print("winse's policy is used")
	jwt.is_valid
	allow_winse #To be defined in your own rego-file
}
######################################################

allow_winse if {
  input.method == "POST"
  print("Allowed because of POST")
}