package lightbulbs

import rego.v1

default allow_welle = false

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow_welle if {
	correct_path
	"policy", "Welle" in input.uri_args
	print("NAME's policy is used")
	jwt.is_valid
	allow_welle 
}
######################################################

allow_welle if {
  input.method == "POST"
  print("Allowed because of POST")
}
