package lightbulbs

import rego.v1

default allow_timo = false

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "timo" in input.uri_args
	print("timo's policy is used")
	jwt.is_valid
	allow_timo #To be defined in your own rego-file
}
######################################################

allow_timo if {
  input.method == "POST"
  print("Allowed because of POST")
}

allow_timo if {
  input.method == "PUT"
  print("Allowed because of POST")
}
