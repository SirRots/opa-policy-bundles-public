package lightbulbs

import rego.v1

default allow_niels = true

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "niels" in input.uri_args
	print("niels's policy is used")
	jwt.is_valid
	allow_niels #To be defined in your own rego-file
}
######################################################

allow_niels if {
  input.method == "POST"
  print("Allowed because of POST")
}

allow_niels if {
  input.method == "PUT" 
  print("Allowed because of Lucifer")
}

