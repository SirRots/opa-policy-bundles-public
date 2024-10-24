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

allow_winse if {
  input.method == "GET"
  print("Allowed because of GET")
}

allow_winse if {
get_owner(id)==jwt.claims.sub 
  input.method == "PUT"
  print("Allowed because of PUT")
}

allow_winse if {
get_owner(id)== 
  input.method == "DELETE"
  print("Allowed because of DELETE")
}
