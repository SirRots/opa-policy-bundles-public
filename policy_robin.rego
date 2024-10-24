package lightbulbs

import rego.v1

default allow_ROBIN = false

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "ROBIN" in input.uri_args
	print("ROBIN's policy is used")
	jwt.is_valid
	allow_ROBIN #To be defined in your own rego-file
}
######################################################

allow_ROBIN if {
  input.method == "POST"
  print("Allowed because of POST")
}
