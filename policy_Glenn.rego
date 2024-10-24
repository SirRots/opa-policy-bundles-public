package lightbulbs

import rego.v1

default allow_Glenn = false

######################################################
#####     Substitute Glenn for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "Glenn" in input.uri_args
	print("Glenn's policy is used")
	jwt.is_valid
	allow_Glenn #To be defined in your own rego-file
}
######################################################

allow_Glenn if {
  get_owner(id) == null
  input.method == "POST"
  print("Allowed because of POST")
}
